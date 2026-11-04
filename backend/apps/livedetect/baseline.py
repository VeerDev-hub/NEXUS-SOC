"""Behavioural baselines (UEBA-lite) for live detection.

Signature rules catch known attack patterns. Baselines catch the *unusual*: a valid
account logging in from an address it never used, at 03:00, onto a server it never
touched; an administrator using sudo for the first time; a binary that never ran on
a host before, started from a Temp folder.

How it works
------------
* Every live event is reduced to zero or more observations (``logon``, ``process``,
  ``privilege``) about a user and/or a host.
* Each user and host has an ``EntityProfile`` with bounded frequency tables (source
  IPs, hosts, hour-of-day histogram, processes, sudo use). Profiles are persisted, so
  learning survives restarts, and can be trained from historical logs with
  ``manage.py build_baseline``.
* An observation is first *compared* with the profile, then *learned*. Comparison only
  happens once the profile is mature (enough observations over a long enough period),
  so a fresh install does not alert on everything.
* Deviations are scored and combined per event (e.g. new IP + unusual hour = one
  "anomalous logon" alert with both reasons). Each entity also keeps a decaying risk
  score; several moderate anomalies in a day escalate to High.

Everything is a pure in-process computation (dict lookups), so it adds microseconds
per event and keeps live detection low-latency.
"""

import ipaddress
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from apps.alerts.models import AlertTactic, ProductCategory, Severity

from .rules import Rule

logger = logging.getLogger(__name__)

USER = "user"
HOST = "host"

MAX_TABLE_KEYS = {"src_ips": 200, "hosts": 200, "users": 500, "processes": 3000, "privilege": 100}

# ---------------------------------------------------------------------------
# Rules (used for titles, MITRE mapping and alert metadata; severity is per anomaly)
# ---------------------------------------------------------------------------


def _never(_event):  # baseline rules are not evaluated by the signature engine
    return None


ANOMALOUS_LOGON = Rule(
    id="ueba.anomalous_logon",
    title="Anomalous logon for {user} on {host}: {anomaly_headline}",
    description="A successful logon deviated from the account's learned behaviour (source address, target host or time of day).",
    severity=Severity.MEDIUM,
    tactic=AlertTactic.INITIAL_ACCESS,
    technique="T1078 - Valid Accounts",
    category=ProductCategory.UEBA,
    match=_never,
    group_by=("user", "host", "src_ip"),
    mitigation="Confirm the logon with the account owner; if unexpected, reset the credentials, revoke sessions and review activity from the source address.",
    tags=("ueba", "behavioural-anomaly", "logon"),
)

FIRST_PRIVILEGE_USE = Rule(
    id="ueba.first_privilege_use",
    title="First privileged command by {user} on {host}",
    description="An account used sudo where its learned baseline shows no prior privileged activity.",
    severity=Severity.MEDIUM,
    tactic=AlertTactic.PRIVILEGE_ESCALATION,
    technique="T1548.003 - Sudo and Sudo Caching",
    category=ProductCategory.UEBA,
    match=_never,
    group_by=("user", "host"),
    mitigation="Verify the change was authorised; review sudoers membership and the command that was run.",
    tags=("ueba", "behavioural-anomaly", "privilege"),
)

RARE_PROCESS = Rule(
    id="ueba.rare_process",
    title="Never-before-seen process {process_name} on {host}",
    description="A process started that is absent from the host's learned process baseline.",
    severity=Severity.LOW,
    tactic=AlertTactic.EXECUTION,
    technique="T1204 - User Execution",
    category=ProductCategory.UEBA,
    match=_never,
    group_by=("host", "process"),
    mitigation="Check the binary's signature, hash reputation and parent process; quarantine it if it is not expected software.",
    tags=("ueba", "behavioural-anomaly", "process"),
)

BASELINE_RULES = (ANOMALOUS_LOGON, FIRST_PRIVILEGE_USE, RARE_PROCESS)


def severity_for(score):
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------

_LOGON_TYPES = {"2", "3", "7", "8", "10", "11"}  # interactive, network, unlock, cleartext, RDP, cached
_LOGON_TYPE_NAMES = {"2": "interactive", "3": "network", "7": "unlock", "8": "network-cleartext", "10": "RDP", "11": "cached"}
_IGNORED_USERS = {"", "-", "system", "local service", "network service", "anonymous logon", "localsystem", "nobody"}
_IGNORED_USER_PREFIXES = ("dwm-", "umfd-", "font driver host", "window manager", "nt authority", "nt service")

_LINUX_LOGON = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic) for (?P<user>\S+) from (?P<src_ip>\S+)")
_SUDO = re.compile(r"^\s*(?P<user>[^\s:]+)\s*:(?!.*\b(?:incorrect password attempts?|NOT in sudoers|command not allowed)\b).*?\bCOMMAND=(?P<command>.+)$")
_GENERIC_LOGON = re.compile(
    r"\b(?:logged in|log(?:ged)?[ -]?on succe\w+|login (?:succeeded|successful|success)|successful(?:ly)? (?:login|logon|logged in|authenticated)|authentication succeeded)\b",
    re.I,
)
_SUSPICIOUS_PATH = re.compile(
    r"(\\users\\[^\\]+\\(appdata|downloads|desktop|documents)\\|\\temp\\|\\windows\\temp\\|\\programdata\\[^\\]+\.exe$|\\users\\public\\|\\\$recycle\.bin\\|^/tmp/|^/var/tmp/|^/dev/shm/|/\.[^/]+/)",
    re.I,
)


@dataclass
class Observation:
    kind: str  # logon / process / privilege
    user: str = ""
    host: str = ""
    src_ip: str = ""
    process: str = ""
    command: str = ""
    detail: dict = field(default_factory=dict)


def normalize_user(name):
    name = str(name or "").strip().strip('"').lower()
    if "\\" in name:
        name = name.split("\\")[-1]
    return name


def is_service_account(user):
    return user in _IGNORED_USERS or user.endswith("$") or user.startswith(_IGNORED_USER_PREFIXES)


def normalize_host(host):
    return str(host or "").strip().lower()


def normalize_process(process):
    return str(process or "").strip().strip('"').lower()


def process_name(process):
    return re.split(r"[\\/]", process)[-1] if process else ""


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(str(value).split("%")[0])
    except ValueError:
        return False
    return ip.is_global


def extract_observations(event):
    """Reduce one ``LogEvent`` to behavioural observations (often none)."""
    observations = []
    fields = event.fields or {}
    if event.source == "windows":
        data = fields.get("data") or {}
        if event.event_id == 4624 and fields.get("logon_type") in _LOGON_TYPES:
            observations.append(Observation(
                "logon",
                user=normalize_user(fields.get("target_user")),
                host=normalize_host(event.host),
                src_ip=str(fields.get("src_ip") or ""),
                detail={"logon_type": _LOGON_TYPE_NAMES.get(fields.get("logon_type"), fields.get("logon_type"))},
            ))
        elif event.event_id == 4688 or (event.event_id == 1 and "sysmon" in event.program.lower()):
            observations.append(Observation(
                "process",
                user=normalize_user(fields.get("actor_user") or data.get("User")),
                host=normalize_host(event.host),
                process=normalize_process(fields.get("process") or data.get("Image")),
                command=str(fields.get("command") or ""),
            ))
    else:
        message = event.message or ""
        program = (event.program or "").lower()
        match = _LINUX_LOGON.search(message)
        if match:
            observations.append(Observation(
                "logon", user=normalize_user(match["user"]), host=normalize_host(event.host), src_ip=match["src_ip"], detail={"logon_type": program or "ssh"},
            ))
        elif program.startswith("sudo"):
            match = _SUDO.search(message)
            if match:
                observations.append(Observation(
                    "privilege", user=normalize_user(match["user"]), host=normalize_host(event.host), command=match["command"].strip(),
                ))
        elif fields.get("user") and _GENERIC_LOGON.search(message):
            observations.append(Observation(
                "logon", user=normalize_user(fields["user"]), host=normalize_host(event.host), src_ip=str(fields.get("src_ip") or ""), detail={"logon_type": program or "application"},
            ))
    return [
        obs for obs in observations
        if (obs.kind == "process" and obs.host and obs.process) or (obs.kind != "process" and obs.user and not is_service_account(obs.user))
    ]


# ---------------------------------------------------------------------------
# Profiles and their store
# ---------------------------------------------------------------------------


@dataclass
class Profile:
    entity_type: str
    entity: str
    first_seen: object
    last_seen: object
    observations: int = 0
    data: dict = field(default_factory=dict)
    risk_score: float = 0.0
    risk_updated_at: object = None
    anomaly_count: int = 0
    last_anomaly_at: object = None
    last_anomaly: dict = field(default_factory=dict)
    pk: int | None = None
    dirty: bool = False

    def table(self, name):
        value = self.data.get(name)
        if not isinstance(value, dict):
            value = self.data[name] = {}
        return value

    def hours(self):
        value = self.data.get("hours")
        if not isinstance(value, list) or len(value) != 24:
            value = self.data["hours"] = [0] * 24
        return value

    def bump(self, name, key, amount=1):
        if not key:
            return
        table = self.table(name)
        table[key] = table.get(key, 0) + amount
        limit = MAX_TABLE_KEYS.get(name, 500)
        if len(table) > limit:  # forget the rarest value, keep the table bounded
            del table[min(table, key=table.get)]

    def touch(self, now):
        self.observations += 1
        if now < self.first_seen:
            self.first_seen = now
        if now > self.last_seen:
            self.last_seen = now
        self.dirty = True

    @property
    def age(self):
        return self.last_seen - self.first_seen

    def current_risk(self, now, half_life_hours):
        if not self.risk_score or self.risk_updated_at is None:
            return float(self.risk_score or 0)
        hours = max(0.0, (now - self.risk_updated_at).total_seconds() / 3600)
        return self.risk_score * 0.5 ** (hours / half_life_hours)

    def add_risk(self, points, now, half_life_hours, anomaly):
        self.risk_score = min(100.0, self.current_risk(now, half_life_hours) + points)
        self.risk_updated_at = now
        self.anomaly_count += 1
        self.last_anomaly_at = now
        self.last_anomaly = anomaly
        self.dirty = True
        return self.risk_score


_PROFILE_FIELDS = ("first_seen", "last_seen", "observations", "data", "risk_score", "risk_updated_at", "anomaly_count", "last_anomaly_at", "last_anomaly")


class ProfileStore:
    """Caches profiles in memory and writes changed ones to the database on ``flush``."""

    def __init__(self, *, persist=True):
        self.persist = persist
        self._cache = {}

    def get(self, entity_type, entity, now):
        key = (entity_type, entity)
        profile = self._cache.get(key)
        if profile is None:
            profile = self._load(entity_type, entity) or Profile(entity_type, entity, first_seen=now, last_seen=now)
            self._cache[key] = profile
        return profile

    def peek(self, entity_type, entity):
        return self._cache.get((entity_type, entity))

    def _load(self, entity_type, entity):
        if not self.persist:
            return None
        from .models import EntityProfile

        row = EntityProfile.objects.filter(entity_type=entity_type, entity=entity).first()
        if row is None:
            return None
        return Profile(entity_type, entity, pk=row.pk, **{name: getattr(row, name) for name in _PROFILE_FIELDS})

    def flush(self):
        dirty = [p for p in self._cache.values() if p.dirty]
        if not self.persist or not dirty:
            for profile in dirty:
                profile.dirty = False
            return 0
        from .models import EntityProfile

        saved = 0
        for profile in dirty:
            values = {name: getattr(profile, name) for name in _PROFILE_FIELDS}
            try:
                row, _ = EntityProfile.objects.update_or_create(entity_type=profile.entity_type, entity=profile.entity[:255], defaults=values)
                profile.pk = row.pk
                profile.dirty = False
                saved += 1
            except Exception:
                logger.exception("Could not save baseline profile %s:%s", profile.entity_type, profile.entity)
        return saved


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


@dataclass
class Anomaly:
    rule: Rule
    score: int
    reasons: list
    fields: dict

    @property
    def severity(self):
        return severity_for(self.score)


def _setting(name, default):
    return getattr(settings, name, default)


def usual_hours(hours, coverage=0.8):
    """Smallest set of hours covering ``coverage`` of activity, as a readable range list."""
    total = sum(hours)
    if not total:
        return ""
    chosen, running = set(), 0
    for hour in sorted(range(24), key=lambda h: -hours[h]):
        if running >= coverage * total:
            break
        chosen.add(hour)
        running += hours[hour]
    ranges, start = [], None
    for hour in range(25):
        if hour < 24 and hour in chosen:
            start = hour if start is None else start
        elif start is not None:
            ranges.append(f"{start:02d}:00-{hour:02d}:00")
            start = None
    return ", ".join(ranges)


class BaselineEngine:
    def __init__(
        self,
        *,
        store=None,
        min_observations=None,
        min_age_hours=None,
        min_process_events=None,
        rare_hour_ratio=None,
        min_alert_score=None,
        risk_half_life_hours=None,
        process_alerts_per_hour=None,
        learn_only=False,
    ):
        self.store = store if store is not None else ProfileStore()
        self.min_observations = min_observations if min_observations is not None else _setting("UEBA_MIN_OBSERVATIONS", 10)
        self.min_age = timedelta(hours=min_age_hours if min_age_hours is not None else _setting("UEBA_MIN_AGE_HOURS", 24))
        self.min_process_events = min_process_events if min_process_events is not None else _setting("UEBA_MIN_PROCESS_EVENTS", 200)
        self.rare_hour_ratio = rare_hour_ratio if rare_hour_ratio is not None else _setting("UEBA_RARE_HOUR_RATIO", 0.03)
        self.min_alert_score = min_alert_score if min_alert_score is not None else _setting("UEBA_MIN_ALERT_SCORE", 30)
        self.half_life = risk_half_life_hours if risk_half_life_hours is not None else _setting("UEBA_RISK_HALF_LIFE_HOURS", 24)
        self.process_alerts_per_hour = process_alerts_per_hour if process_alerts_per_hour is not None else _setting("UEBA_PROCESS_ALERTS_PER_HOUR", 5)
        self.learn_only = learn_only
        self._process_alerts = defaultdict(deque)
        self.stats = defaultdict(int)

    def is_mature(self, profile, count=None):
        count = profile.observations if count is None else count
        return count >= self.min_observations and profile.age >= self.min_age

    def observe(self, event):
        anomalies = []
        for obs in extract_observations(event):
            self.stats[f"observations.{obs.kind}"] += 1
            handler = {"logon": self._logon, "process": self._process, "privilege": self._privilege}[obs.kind]
            try:
                anomaly = handler(obs, event.timestamp)
            except Exception:
                logger.exception("Baseline failed on %s observation", obs.kind)
                continue
            if anomaly is not None and not self.learn_only:
                self.stats["anomalies"] += 1
                anomalies.append(anomaly)
        return anomalies

    def flush(self):
        return self.store.flush()

    # -- per observation kind ---------------------------------------------

    def _logon(self, obs, now):
        user = self.store.get(USER, obs.user, now)
        logons = int(user.data.get("logons", 0))
        reasons, score, headline = [], 0, []
        known_ips = user.table("src_ips")
        known_hosts = user.table("hosts")
        hours = user.hours()
        hour = timezone.localtime(now).hour
        if self.is_mature(user, logons):
            if obs.src_ip and known_ips and obs.src_ip not in known_ips:
                points = 40 if len(known_ips) <= 10 else 20
                text = f"first logon from source IP {obs.src_ip} ({len(known_ips)} address(es) seen in {logons} logons)"
                if is_public_ip(obs.src_ip) and not any(is_public_ip(ip) for ip in known_ips):
                    points += 20
                    text += "; the account has only ever logged on from internal addresses before"
                reasons.append(text)
                score += points
                headline.append(f"new source {obs.src_ip}")
            if obs.host and known_hosts and obs.host not in known_hosts:
                points = 30 if len(known_hosts) <= 20 else 10
                reasons.append(f"first logon to host {obs.host} (usually {', '.join(sorted(known_hosts, key=known_hosts.get, reverse=True)[:3])})")
                score += points
                headline.append("new host")
            total = sum(hours)
            near = hours[(hour - 1) % 24] + hours[hour] + hours[(hour + 1) % 24]
            if total and near / total < self.rare_hour_ratio:
                reasons.append(f"logon at {hour:02d}:00 is outside the usual hours ({usual_hours(hours)})")
                score += 25
                headline.append("unusual hour")

        snapshot = {
            "logons": logons,
            "known_source_ips": sorted(known_ips, key=known_ips.get, reverse=True)[:5],
            "known_hosts": sorted(known_hosts, key=known_hosts.get, reverse=True)[:5],
            "usual_hours": usual_hours(hours),
            "learning_since": user.first_seen.isoformat(),
        }
        # learn after comparing
        user.data["logons"] = logons + 1
        user.bump("src_ips", obs.src_ip)
        user.bump("hosts", obs.host)
        hours[hour] += 1
        user.touch(now)
        if obs.host:
            host = self.store.get(HOST, obs.host, now)
            host.bump("users", obs.user)
            host.data["logons"] = int(host.data.get("logons", 0)) + 1
            host.touch(now)

        if not reasons:
            return None
        return self._anomaly(
            ANOMALOUS_LOGON,
            user,
            score,
            reasons,
            now,
            {
                "user": obs.user,
                "host": obs.host,
                "src_ip": obs.src_ip,
                "logon_type": obs.detail.get("logon_type", ""),
                "anomaly_headline": ", ".join(headline),
                "baseline": snapshot,
            },
        )

    def _privilege(self, obs, now):
        user = self.store.get(USER, obs.user, now)
        used = user.table("privilege")
        snapshot = {"privileged_hosts": sorted(used)[:5], "learning_since": user.first_seen.isoformat()}
        reasons, score = [], 0
        if self.is_mature(user):
            if not used:
                reasons.append(f"{obs.user} has never used sudo in {user.observations} recorded activities since {user.first_seen:%Y-%m-%d}")
                score = 50
            elif obs.host and obs.host not in used:
                reasons.append(f"{obs.user} has used sudo before, but never on {obs.host}")
                score = 35
        user.bump("privilege", obs.host or "unknown")
        user.touch(now)
        if not reasons:
            return None
        return self._anomaly(
            FIRST_PRIVILEGE_USE,
            user,
            score,
            reasons,
            now,
            {"user": obs.user, "host": obs.host, "command": obs.command[:2000], "baseline": snapshot},
        )

    def _process(self, obs, now):
        host = self.store.get(HOST, obs.host, now)
        seen = host.table("processes")
        events = int(host.data.get("process_events", 0))
        snapshot = {"known_processes": len(seen), "process_events": events, "learning_since": host.first_seen.isoformat()}
        reasons, score = [], 0
        if events >= self.min_process_events and host.age >= self.min_age and obs.process not in seen:
            reasons.append(f"{process_name(obs.process)} has not run on {obs.host} in {events} process starts since {host.first_seen:%Y-%m-%d}")
            score = 30
            if _SUSPICIOUS_PATH.search(obs.process):
                reasons.append(f"it started from a user-writable location ({obs.process})")
                score += 30
        host.bump("processes", obs.process)
        host.data["process_events"] = events + 1
        host.touch(now)
        if not reasons:
            return None
        budget = self._process_alerts[obs.host]
        while budget and now - budget[0] > timedelta(hours=1):
            budget.popleft()
        if len(budget) >= self.process_alerts_per_hour and score < 60:
            self.stats["suppressed.rare_process"] += 1
            return None
        budget.append(now)
        return self._anomaly(
            RARE_PROCESS,
            host,
            score,
            reasons,
            now,
            {
                "host": obs.host,
                "process": obs.process,
                "process_name": process_name(obs.process),
                "command": obs.command[:2000],
                "user": obs.user if obs.user and not is_service_account(obs.user) else "",
                "baseline": snapshot,
            },
        )

    def _anomaly(self, rule, profile, score, reasons, now, fields):
        score = min(100, score)
        before = profile.current_risk(now, self.half_life)
        record = {"rule": rule.id, "score": score, "reasons": reasons, "time": now.isoformat()}
        risk = profile.add_risk(score, now, self.half_life, record)
        # Escalate only when the entity was already carrying meaningful risk from earlier anomalies.
        if risk >= 80 and before >= 40:
            reasons = [*reasons, f"{profile.entity_type} {profile.entity} risk score is {risk:.0f}/100 after repeated anomalies in the last {self.half_life:g}h"]
            score = max(score, 70)
        if score < self.min_alert_score:
            self.stats["below_threshold"] += 1
            return None
        fields = {
            **fields,
            "anomaly_score": score,
            "anomaly_reasons": reasons,
            "entity_risk": round(risk),
        }
        return Anomaly(rule=replace(rule, severity=severity_for(score)), score=score, reasons=reasons, fields=fields)
