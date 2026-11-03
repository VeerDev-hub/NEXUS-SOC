"""Stateful real-time detection engine.

``DetectionEngine.process(event)`` runs every rule against one live event, keeps
sliding windows for threshold/correlation rules, suppresses repeats with a cooldown
and hands each detection to ``emit`` (by default: create an alert + case, which
queues the multi-agent analysis).

The engine is not thread-safe; the live detection command feeds it from one thread.
"""

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta

from apps.agentic.runtime.base import generate_correlation_uid, parse_event_time
from apps.agentic.services.alerts import create_alert_with_context
from apps.alerts.models import (
    AlertAction,
    AlertAnalyticType,
    AlertRiskLevel,
    AlertStatus,
    Confidence,
    Disposition,
    Impact,
)
from apps.artifacts.models import ArtifactName, ArtifactRole, ArtifactType
from apps.cases.models import CaseConfidence, CaseImpact, CasePriority

from .events import LogEvent
from .rules import RULES, Rule

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass
class Detection:
    rule: Rule
    fields: dict
    count: int
    event: LogEvent
    evidence: list = field(default_factory=list)  # recent matching events (dicts)

    @property
    def title(self):
        return format_title(self.rule.title, self.fields)


class _Missing(dict):
    def __missing__(self, key):
        return "unknown"


def format_title(template, fields):
    return template.format_map(_Missing({k: v for k, v in fields.items() if v not in (None, "")}))


class DetectionEngine:
    def __init__(self, rules=None, *, emit=None, cooldown_seconds=600):
        self.rules = list(rules if rules is not None else RULES)
        self.emit = emit if emit is not None else create_detection_alert
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self._hits = defaultdict(deque)  # (rule_id, key) -> deque[(ts, distinct_value, fields_dict)]
        self._last_fired = {}
        self._max_window = timedelta(seconds=max([r.window_seconds for r in self.rules] + [r.after.window_seconds for r in self.rules if r.after] + [60]))
        self._processed = 0
        self.stats = defaultdict(int)

    # -- public -----------------------------------------------------------

    def process(self, event):
        detections = []
        self._processed += 1
        self.stats["events"] += 1
        for rule in self.rules:
            if not rule.applies_to(event):
                continue
            try:
                matched = rule.match(event)
            except Exception:
                logger.exception("Rule %s crashed on event from %s", rule.id, event.channel or event.source)
                continue
            if matched is None:
                continue
            detection = self._evaluate(rule, event, matched)
            if detection is not None:
                detections.append(detection)
        if self._processed % 2000 == 0:
            self._collect_garbage(event.timestamp)
        for detection in detections:
            self.stats[detection.rule.id] += 1
            self.stats["detections"] += 1
            try:
                self.emit(detection)
            except Exception:
                logger.exception("Failed to record detection %s", detection.rule.id)
        return detections

    # -- internals --------------------------------------------------------

    def _key(self, rule, fields):
        return tuple(str(fields.get(name, "")) for name in rule.group_by)

    def _window(self, rule_id, key, now, window):
        hits = self._hits.get((rule_id, key))
        if not hits:
            return deque()
        cutoff = now - window
        while hits and hits[0][0] < cutoff:
            hits.popleft()
        return hits

    def _evaluate(self, rule, event, matched):
        fields = {"host": event.host, **{k: v for k, v in matched.items() if v not in (None, "")}}
        fields.setdefault("host", event.host)
        key = self._key(rule, fields)
        now = event.timestamp
        hits = self._hits[(rule.id, key)]
        hits.append((now, fields.get(rule.distinct) if rule.distinct else None, {**fields, "_event": event.as_dict()}))
        hits = self._window(rule.id, key, now, timedelta(seconds=rule.window_seconds))

        if not rule.alert:
            return None
        count = len({value for _, value, _ in hits}) if rule.distinct else len(hits)
        if count < rule.threshold:
            return None
        if rule.after is not None:
            prior_rule = next((r for r in self.rules if r.id == rule.after.rule_id), None)
            prior_key = self._key(prior_rule, fields) if prior_rule else key
            prior = self._window(rule.after.rule_id, prior_key, now, timedelta(seconds=rule.after.window_seconds))
            if len(prior) < rule.after.min_count:
                return None
            count = len(prior)

        fired_key = (rule.id, key)
        last = self._last_fired.get(fired_key)
        if last is not None and abs(now - last) < self.cooldown:
            return None
        self._last_fired[fired_key] = now

        fields["count"] = count
        evidence = [item[2]["_event"] for item in list(hits)[-10:]]
        return Detection(rule=rule, fields=fields, count=count, event=event, evidence=evidence)

    def _collect_garbage(self, now):
        cutoff = now - self._max_window
        for key in [k for k, hits in self._hits.items() if not hits or hits[-1][0] < cutoff]:
            del self._hits[key]
        fired_cutoff = now - self.cooldown
        for key in [k for k, ts in self._last_fired.items() if ts < fired_cutoff]:
            del self._last_fired[key]


# ---------------------------------------------------------------------------
# Detection -> Alert + Case
# ---------------------------------------------------------------------------

_ARTIFACT_FIELDS = [
    ("src_ip", ArtifactType.IP_ADDRESS, ArtifactRole.ACTOR, ArtifactName.SOURCE_IP),
    ("dst_ip", ArtifactType.IP_ADDRESS, ArtifactRole.TARGET, ArtifactName.DESTINATION_IP),
    ("host", ArtifactType.HOSTNAME, ArtifactRole.AFFECTED, ArtifactName.AFFECTED_HOST),
    ("user", ArtifactType.USER_NAME, ArtifactRole.TARGET, ArtifactName.TARGET_USER),
    ("target_user", ArtifactType.USER_NAME, ArtifactRole.TARGET, ArtifactName.TARGET_USER),
    ("actor_user", ArtifactType.USER_NAME, ArtifactRole.ACTOR, ArtifactName.ACTOR_USER),
    ("member", ArtifactType.USER_NAME, ArtifactRole.TARGET, ArtifactName.TARGET_USER),
    ("command", ArtifactType.COMMAND_LINE, ArtifactRole.RELATED, ArtifactName.PROCESS_COMMAND_LINE),
    ("process", ArtifactType.PROCESS_NAME, ArtifactRole.RELATED, ArtifactName.PROCESS_NAME),
    ("url", ArtifactType.URL_STRING, ArtifactRole.TARGET, ArtifactName.REQUEST_URL),
    ("user_agent", ArtifactType.HTTP_USER_AGENT, ArtifactRole.ACTOR, ArtifactName.HTTP_USER_AGENT),
    ("service", ArtifactType.PROCESS_NAME, ArtifactRole.RELATED, ArtifactName.WINDOWS_SERVICE),
    ("file_path", ArtifactType.FILE_PATH, ArtifactRole.RELATED, ArtifactName.FILE_PATH),
]
_ARTIFACT_MAX_LEN = 2000


def detection_artifacts(fields):
    artifacts, seen = [], set()
    for key, type_, role, name in _ARTIFACT_FIELDS:
        value = str(fields.get(key) or "").strip()
        if not value or value.lower() in ("unknown", "-", "n/a"):
            continue
        identity = (type_, role, value.lower())
        if identity in seen:
            continue
        seen.add(identity)
        artifacts.append({"value": value[:_ARTIFACT_MAX_LEN], "type": type_, "role": role, "name": name})
    return artifacts


def _confidence(rule):
    if rule.after is not None or rule.id.startswith("command.") or rule.severity == "Critical":
        return "High"
    return "Medium"


def create_detection_alert(detection):
    rule, fields, event = detection.rule, detection.fields, detection.event
    title = detection.title
    confidence = _confidence(rule)
    impact = rule.severity if rule.severity in ("Low", "Medium", "High", "Critical") else "Unknown"
    keys = [fields.get(name, "") for name in rule.group_by] or [event.host]
    correlation_uid = generate_correlation_uid(rule_id=f"live.{rule.id}", time_window="24h", keys=keys, timestamp=event.timestamp)
    first_seen = event.timestamp
    if detection.evidence:
        first_seen, _ = parse_event_time(detection.evidence[0].get("timestamp"), default=event.timestamp)
    public_fields = {k: v for k, v in fields.items() if not k.startswith("_")}
    # The source path/peer lives in data_sources, not in free text the agents reason over.
    description = f"{rule.description} Detected live by NEXUS-SOC from {event.source} logs. {detection.count} matching event(s)."

    result = create_alert_with_context(
        case_defaults={
            "title": title[:500],
            "severity": rule.severity,
            "impact": impact if impact in CaseImpact.values else CaseImpact.UNKNOWN,
            "priority": rule.severity if rule.severity in CasePriority.values else CasePriority.MEDIUM,
            "confidence": confidence if confidence in CaseConfidence.values else CaseConfidence.MEDIUM,
            "description": description,
            "category": rule.category,
            "tags": ["live-detection", *rule.tags],
            "correlation_uid": correlation_uid,
        },
        alert_fields={
            "title": title[:500],
            "severity": rule.severity,
            "confidence": confidence if confidence in Confidence.values else Confidence.MEDIUM,
            "impact": impact if impact in Impact.values else Impact.UNKNOWN,
            "disposition": Disposition.DETECTED,
            "action": AlertAction.OBSERVED,
            "status": AlertStatus.NEW,
            "rule_id": rule.id,
            "rule_name": rule.title.split(" {")[0][:255],
            "correlation_uid": correlation_uid,
            "source_uid": str(event.fields.get("record_id") or ""),
            "analytic_type": AlertAnalyticType.RULE if rule.threshold == 1 and not rule.after else AlertAnalyticType.STATISTICAL,
            "analytic_name": "NEXUS-SOC Live Detection",
            "analytic_desc": rule.description,
            "product_category": rule.category,
            "product_name": "NEXUS-SOC Live Detection",
            "product_vendor": "NEXUS-SOC",
            "product_feature": f"{event.source} log monitoring",
            "first_seen_time": first_seen,
            "last_seen_time": event.timestamp,
            "desc": description,
            "data_sources": [f"{event.source}:{event.channel}" if event.channel else event.source],
            "labels": ["live-detection", *rule.tags],
            "raw_data": {"event": event.as_dict(), "evidence": detection.evidence},
            "unmapped": {"detection_fields": public_fields, "match_count": detection.count},
            "tactic": rule.tactic,
            "technique": rule.technique,
            "mitigation": rule.mitigation,
            "risk_level": rule.severity if rule.severity in AlertRiskLevel.values else AlertRiskLevel.MEDIUM,
        },
        artifacts=detection_artifacts(fields),
        enrichments=[],
        schedule_analysis=True,
        analysis_trigger=f"live:{rule.id}"[:100],
    )
    logger.warning(
        "LIVE DETECTION %s [%s] %s -> case %s",
        rule.id,
        rule.severity,
        title,
        result.case.case_id or result.case.pk,
    )
    return result
