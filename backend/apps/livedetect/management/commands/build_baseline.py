"""Train behavioural baselines from historical logs (no alerts are raised).

Examples::

    python manage.py build_baseline --windows --days 30          # as Administrator
    python manage.py build_baseline --file /var/log/auth.log* --file access.log
    python manage.py build_baseline --show
"""

import glob
import gzip
import time
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.livedetect.baseline import BaselineEngine
from apps.livedetect.events import parse_file_line, windows_event_from_element
from apps.livedetect.models import EntityProfile
from apps.livedetect.sources import WindowsEventLogSource, _parse_events_xml, _wevtutil

# Successful logons and process creation (Security), Sysmon process creation.
WINDOWS_QUERIES = (
    ("Security", (4624, 4688)),
    ("Microsoft-Windows-Sysmon/Operational", (1,)),
)


class Command(BaseCommand):
    help = "Learn user/host behavioural baselines from historical logs without raising alerts."

    def add_arguments(self, parser):
        parser.add_argument("--file", action="append", default=[], help="Log file or glob to learn from (repeatable; .gz supported).")
        parser.add_argument("--windows", action="store_true", help="Learn from the Windows Security (and Sysmon) event log. Needs Administrator.")
        parser.add_argument("--days", type=int, default=30, help="How far back to read the Windows event log. Default %(default)s.")
        parser.add_argument("--reset", action="store_true", help="Delete all existing profiles first.")
        parser.add_argument("--show", action="store_true", help="Only print the current profiles.")

    def handle(self, *args, **options):
        if options["show"]:
            return self._show()
        if not options["file"] and not options["windows"]:
            raise CommandError("Give --file and/or --windows (or --show).")
        if options["reset"]:
            deleted, _ = EntityProfile.objects.all().delete()
            self.stdout.write(f"Deleted {deleted} existing profile(s).")

        baseline = BaselineEngine(learn_only=True)
        started = time.monotonic()
        events = 0
        for pattern in options["file"]:
            paths = sorted(glob.glob(pattern)) or ([pattern] if Path(pattern).exists() else [])
            if not paths:
                self.stderr.write(self.style.WARNING(f"No files match {pattern}"))
            # Rotated logs (auth.log.2.gz, auth.log.1, auth.log): oldest first.
            for path in sorted(paths, key=lambda p: Path(p).stat().st_mtime):
                count = self._learn_file(baseline, path)
                events += count
                self.stdout.write(f"  {path}: {count} events")
        if options["windows"]:
            if not WindowsEventLogSource.available():
                raise CommandError("--windows is only supported on Windows.")
            for channel, ids in WINDOWS_QUERIES:
                count = self._learn_windows(baseline, channel, ids, options["days"])
                events += count
                self.stdout.write(f"  Windows {channel}: {count} events")

        saved = baseline.flush()
        obs = {k.split(".", 1)[1]: v for k, v in baseline.stats.items() if k.startswith("observations.")}
        self.stdout.write(self.style.SUCCESS(
            f"Learned from {events} events ({obs or 'no relevant activity'}) in {time.monotonic() - started:.1f}s; saved {saved} profile(s)."
        ))
        self._show()

    def _learn_file(self, baseline, path):
        opener = gzip.open if path.endswith(".gz") else open
        count = 0
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                event = parse_file_line(line, channel=path)
                if event is not None:
                    baseline.observe(event)
                    count += 1
        return count

    def _learn_windows(self, baseline, channel, event_ids, days):
        ids = " or ".join(f"EventID={i}" for i in event_ids)
        window_ms = max(1, days) * 86_400_000
        last, count = 0, 0
        while True:
            query = f"*[System[({ids}) and (EventRecordID>{last}) and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]"
            result = _wevtutil(["qe", channel, f"/q:{query}", "/c:2000", "/f:xml", "/e:Events"], timeout=180)
            if result.returncode != 0:
                message = (result.stderr or result.stdout).strip()
                hint = " (run the terminal as Administrator)" if "denied" in message.lower() else ""
                self.stderr.write(self.style.WARNING(f"Cannot read {channel}: {message[:200]}{hint}"))
                return count
            batch = 0
            for element in _parse_events_xml(result.stdout):
                event = windows_event_from_element(element)
                if event is None:
                    continue
                last = max(last, int(event.fields.get("record_id") or 0))
                baseline.observe(event)
                batch += 1
            count += batch
            if batch < 2000:
                return count

    def _show(self):
        profiles = EntityProfile.objects.order_by("entity_type", "-observations")
        if not profiles.exists():
            self.stdout.write("No behavioural profiles yet.")
            return
        now = timezone.now()
        engine = BaselineEngine(learn_only=True)
        self.stdout.write(f"{'type':5} {'entity':32} {'obs':>6} {'since':16} {'state':9} {'risk':>4}  detail")
        for row in profiles[:200]:
            data = row.data or {}
            if row.entity_type == "user":
                count = int(data.get("logons", 0))
                detail = f"{len(data.get('src_ips') or {})} IPs, {len(data.get('hosts') or {})} hosts, sudo on {len(data.get('privilege') or {})}"
                mature = count >= engine.min_observations
            else:
                count = int(data.get("process_events", 0))
                detail = f"{len(data.get('processes') or {})} processes, {len(data.get('users') or {})} users"
                mature = count >= engine.min_process_events
            mature = mature and row.last_seen - row.first_seen >= engine.min_age
            risk = row.risk_score * 0.5 ** (max(0, (now - row.risk_updated_at).total_seconds()) / 3600 / engine.half_life) if row.risk_updated_at else 0
            self.stdout.write(
                f"{row.entity_type:5} {row.entity[:32]:32} {row.observations:>6} {timezone.localtime(row.first_seen):%Y-%m-%d %H:%M} "
                f"{'active' if mature else 'learning':9} {risk:>4.0f}  {detail}"
            )
