import logging
import queue
import signal
import threading
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections

from apps.livedetect.engine import DetectionEngine
from apps.livedetect.rules import RULES
from apps.livedetect.sources import (
    DEFAULT_WINDOWS_CHANNELS,
    FileTailSource,
    SyslogSource,
    WindowsEventLogSource,
)

logger = logging.getLogger("apps.livedetect")


def _csv(value):
    return [item.strip() for item in (value or "").split(",") if item.strip()]


class Command(BaseCommand):
    help = (
        "Run NEXUS-SOC live log detection: listen for syslog, tail log files and read the "
        "Windows Event Log, detect attacks in real time and open cases for the AI agents."
    )

    def add_arguments(self, parser):
        parser.add_argument("--syslog-port", type=int, default=settings.LIVE_SYSLOG_PORT, help="Syslog UDP/TCP port (0 disables). Default %(default)s.")
        parser.add_argument("--syslog-host", default=settings.LIVE_SYSLOG_HOST, help="Address to bind the syslog listener to.")
        parser.add_argument("--no-syslog-tcp", action="store_true", help="Listen for syslog on UDP only.")
        parser.add_argument("--tail", action="append", default=None, help="Log file or glob to follow (repeatable). Default from LIVE_TAIL_FILES.")
        parser.add_argument("--windows", choices=("auto", "on", "off"), default=settings.LIVE_WINDOWS_EVENTLOG, help="Read the Windows Event Log. Default %(default)s.")
        parser.add_argument("--windows-channels", default=",".join(settings.LIVE_WINDOWS_CHANNELS or DEFAULT_WINDOWS_CHANNELS), help="Comma-separated Windows log names.")
        parser.add_argument("--from-start", action="store_true", help="Process existing file/event log content instead of only new entries.")
        parser.add_argument("--cooldown", type=int, default=settings.LIVE_DETECTION_COOLDOWN_SECONDS, help="Seconds before the same rule+key may alert again.")
        parser.add_argument("--list-rules", action="store_true", help="Print the detection rules and exit.")

    def handle(self, *args, **options):
        if options["list_rules"]:
            for rule in RULES:
                extra = f" (>= {rule.threshold} in {rule.window_seconds}s)" if rule.threshold > 1 else ""
                self.stdout.write(f"{rule.id:38} {rule.severity:9} {rule.technique}{extra}")
            return

        events = queue.Queue(maxsize=100_000)
        stop = threading.Event()
        sources = []

        if options["syslog_port"]:
            try:
                sources.append(SyslogSource(events, stop, host=options["syslog_host"], port=options["syslog_port"], tcp=not options["no_syslog_tcp"]))
            except OSError as exc:
                raise CommandError(f"Cannot listen for syslog on port {options['syslog_port']}: {exc}") from exc

        tail_patterns = options["tail"] if options["tail"] is not None else settings.LIVE_TAIL_FILES
        if tail_patterns:
            sources.append(FileTailSource(events, stop, patterns=tail_patterns, from_start=options["from_start"]))

        windows = options["windows"]
        if windows == "on" and not WindowsEventLogSource.available():
            raise CommandError("--windows on is only supported on Windows.")
        if windows == "on" or (windows == "auto" and WindowsEventLogSource.available()):
            sources.append(WindowsEventLogSource(events, stop, channels=_csv(options["windows_channels"]), from_start=options["from_start"]))

        if not sources:
            raise CommandError("No live sources enabled. Use --syslog-port, --tail or --windows on.")

        engine = DetectionEngine(cooldown_seconds=options["cooldown"])
        self.stdout.write(self.style.SUCCESS(f"NEXUS-SOC live detection started with {len(engine.rules)} rules:"))
        for source in sources:
            self.stdout.write(f"  - {source.description}")
            source.start()

        def _stop(*_):
            stop.set()

        signal.signal(signal.SIGINT, _stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _stop)

        last_report = time.monotonic()
        while not stop.is_set():
            try:
                event = events.get(timeout=1)
            except queue.Empty:
                event = None
            if event is not None:
                # Drop DB connections that went stale while the sources were quiet.
                close_old_connections()
                for detection in engine.process(event):
                    self.stdout.write(self.style.WARNING(f"[{detection.rule.severity}] {detection.title}  ({detection.rule.id})"))
            if time.monotonic() - last_report > 60:
                last_report = time.monotonic()
                logger.info("Live detection: %s events processed, %s detections", engine.stats["events"], engine.stats["detections"])

        self.stdout.write("Stopping live detection...")
        for source in sources:
            source.join(timeout=3)
