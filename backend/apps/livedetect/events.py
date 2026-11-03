"""Normalised log events and the parsers that turn raw log lines into them.

Every live source (syslog listener, file tailer, Windows Event Log reader) produces
``LogEvent`` objects, so detection rules only need to understand one shape.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote_plus
from xml.etree import ElementTree

from dateutil import parser as date_parser
from django.utils import timezone


@dataclass
class LogEvent:
    source: str  # "syslog", "file" or "windows"
    message: str
    timestamp: datetime = field(default_factory=timezone.now)
    host: str = ""
    program: str = ""
    channel: str = ""  # Windows log name, file path or syslog peer
    event_id: int | None = None
    fields: dict = field(default_factory=dict)
    raw: str = ""

    def as_dict(self):
        return {
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "program": self.program,
            "channel": self.channel,
            "event_id": self.event_id,
            "message": self.message,
            "fields": self.fields,
            "raw": self.raw[:4000],
        }


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _aware(dt):
    if dt.tzinfo is None:
        return timezone.make_aware(dt, timezone.get_current_timezone())
    return dt


def _parse_time(value):
    if not value:
        return timezone.now()
    try:
        return _aware(date_parser.parse(value))
    except (ValueError, OverflowError, TypeError):
        return timezone.now()


def _parse_bsd_time(value):
    """RFC 3164 timestamps ("Nov  3 14:05:01") carry no year."""
    now = timezone.localtime()
    try:
        parsed = datetime.strptime(f"{now.year} {' '.join(value.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return timezone.now()
    parsed = _aware(parsed)
    if parsed - now > timedelta(days=1):  # December log read in January
        parsed = parsed.replace(year=now.year - 1)
    return parsed


# ---------------------------------------------------------------------------
# Syslog and plain text log lines (auth.log, syslog, messages, ...)
# ---------------------------------------------------------------------------

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|(?:\[.*?\])+)\s?(?P<msg>.*)$",
    re.S,
)
_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>[^\]]*)\])?:\s?(?P<msg>.*)$",
    re.S,
)
_ISO_SYSLOG = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>[^\]]*)\])?:\s?(?P<msg>.*)$",
    re.S,
)
_NGINX_COMBINED = re.compile(
    r'^(?P<src_ip>\S+) \S+ (?P<remote_user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)(?: (?P<protocol>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)


def parse_syslog_line(line, *, source="syslog", channel="", default_host=""):
    line = line.strip("\r\n\x00")
    if not line.strip():
        return None

    match = _RFC5424.match(line)
    if match:
        app = match["app"] if match["app"] != "-" else ""
        return LogEvent(
            source=source,
            message=match["msg"].lstrip("﻿").strip(),
            timestamp=_parse_time(match["ts"] if match["ts"] != "-" else ""),
            host=match["host"] if match["host"] != "-" else default_host,
            program=app,
            channel=channel,
            fields={"pid": match["pid"] if match["pid"] != "-" else ""},
            raw=line,
        )

    for pattern, time_parser in ((_RFC3164, _parse_bsd_time), (_ISO_SYSLOG, _parse_time)):
        match = pattern.match(line)
        if match:
            return LogEvent(
                source=source,
                message=match["msg"].strip(),
                timestamp=time_parser(match["ts"]),
                host=match["host"],
                program=match["tag"],
                channel=channel,
                fields={"pid": match["pid"] or ""},
                raw=line,
            )

    # Unknown format: keep the whole line so keyword rules still see it.
    stripped = re.sub(r"^<\d{1,3}>", "", line).strip()
    return LogEvent(source=source, message=stripped, host=default_host, channel=channel, raw=line)


# ---------------------------------------------------------------------------
# Web access logs (nginx / Apache combined format)
# ---------------------------------------------------------------------------

def parse_access_log_line(line, *, source="file", channel="", default_host=""):
    match = _NGINX_COMBINED.match(line.strip())
    if not match:
        return None
    url = match["url"]
    try:
        ts = _aware(datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        ts = timezone.now()
    return LogEvent(
        source=source,
        message=f'{match["method"]} {url} {match["status"]}',
        timestamp=ts,
        host=default_host,
        program="http",
        channel=channel,
        fields={
            "src_ip": match["src_ip"],
            "method": match["method"],
            "url": url,
            "decoded_url": unquote_plus(unquote_plus(url)),
            "status": int(match["status"]),
            "user_agent": match["user_agent"] or "",
            "referrer": match["referrer"] or "",
        },
        raw=line.strip(),
    )


# ---------------------------------------------------------------------------
# JSON lines (Filebeat/Winlogbeat/ECS-ish or any app that logs JSON)
# ---------------------------------------------------------------------------

def _dig(data, *paths):
    for path in paths:
        if path in data and not isinstance(data[path], dict):
            return data[path]
        current = data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, "") and not isinstance(current, dict):
            return current
    return ""


def parse_json_line(line, *, source="file", channel="", default_host=""):
    try:
        data = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    message = _dig(data, "message", "msg", "log", "event.original")
    if not message:
        message = json.dumps(data, ensure_ascii=False)[:4000]
    event_id = _dig(data, "event.code", "winlog.event_id", "EventID", "event_id")
    try:
        event_id = int(event_id) if event_id != "" else None
    except (TypeError, ValueError):
        event_id = None
    fields = {}
    for key, paths in {
        "src_ip": ("source.ip", "src_ip", "client.ip", "remote_addr"),
        "user": ("user.name", "user", "username"),
        "command": ("process.command_line", "command_line", "cmdline"),
        "url": ("url.original", "url", "request"),
        "user_agent": ("user_agent.original", "user_agent", "http_user_agent"),
    }.items():
        value = _dig(data, *paths)
        if value != "":
            fields[key] = str(value)
    return LogEvent(
        source=source,
        message=str(message),
        timestamp=_parse_time(str(_dig(data, "@timestamp", "timestamp", "time", "ts"))),
        host=str(_dig(data, "host.name", "hostname", "host", "agent.hostname") or default_host),
        program=str(_dig(data, "process.name", "program", "app", "service.name", "logger")),
        channel=channel,
        event_id=event_id,
        fields=fields,
        raw=line.strip(),
    )


def parse_file_line(line, *, channel="", default_host=""):
    """Best-effort parser for a line read from a tailed file."""
    text = line.strip()
    if not text:
        return None
    if text.startswith("{"):
        event = parse_json_line(text, channel=channel, default_host=default_host)
        if event:
            return event
    event = parse_access_log_line(text, channel=channel, default_host=default_host)
    if event:
        return event
    return parse_syslog_line(text, source="file", channel=channel, default_host=default_host)


# ---------------------------------------------------------------------------
# Windows Event Log XML (wevtutil /f:xml)
# ---------------------------------------------------------------------------

_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# EventData names that are useful as normalised fields.
_WINDOWS_FIELD_MAP = {
    "IpAddress": "src_ip",
    "TargetUserName": "target_user",
    "SubjectUserName": "actor_user",
    "MemberName": "member",
    "CommandLine": "command",
    "NewProcessName": "process",
    "ScriptBlockText": "command",
    "ServiceName": "service",
    "ImagePath": "command",
    "TaskName": "task",
    "LogonType": "logon_type",
    "WorkstationName": "workstation",
    "Threat Name": "threat",
    "Path": "file_path",
}


def parse_windows_event_xml(xml_text):
    """Parse one ``<Event>`` element (string) into a LogEvent."""
    root = ElementTree.fromstring(xml_text)
    return windows_event_from_element(root)


def windows_event_from_element(root):
    system = root.find(f"{_EVENT_NS}System")
    if system is None:
        return None

    def sys_text(tag):
        node = system.find(f"{_EVENT_NS}{tag}")
        return node.text.strip() if node is not None and node.text else ""

    provider = system.find(f"{_EVENT_NS}Provider")
    created = system.find(f"{_EVENT_NS}TimeCreated")
    try:
        event_id = int(sys_text("EventID"))
    except ValueError:
        event_id = None

    data = {}
    for container in ("EventData", "UserData"):
        node = root.find(f"{_EVENT_NS}{container}")
        if node is None:
            continue
        for index, item in enumerate(node.iter()):
            if item is node:
                continue
            name = item.get("Name") or item.tag.replace(_EVENT_NS, "").split("}")[-1]
            if item.text and item.text.strip():
                data[name if name != "Data" else f"Data{index}"] = item.text.strip()

    fields = {"record_id": sys_text("EventRecordID"), "data": data}
    for source_name, target in _WINDOWS_FIELD_MAP.items():
        value = data.get(source_name, "")
        if value and value not in ("-", "::1", "127.0.0.1") and target not in fields:
            fields[target] = value
    if event_id == 4104:  # PowerShell script block: keep the script as the command
        fields["command"] = data.get("ScriptBlockText", "")

    message = f"EventID {event_id} {provider.get('Name') if provider is not None else ''}: " + " ".join(
        f"{key}={value}" for key, value in data.items()
    )
    return LogEvent(
        source="windows",
        message=message[:8000],
        timestamp=_parse_time(created.get("SystemTime") if created is not None else ""),
        host=sys_text("Computer"),
        program=provider.get("Name", "") if provider is not None else "",
        channel=sys_text("Channel"),
        event_id=event_id,
        fields=fields,
        raw=ElementTree.tostring(root, encoding="unicode")[:8000],
    )
