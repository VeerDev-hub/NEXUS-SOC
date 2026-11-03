"""Live log sources. Each source runs in its own thread and puts LogEvents on a queue."""

import glob
import logging
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from xml.etree import ElementTree

from .events import parse_file_line, parse_syslog_line, windows_event_from_element

logger = logging.getLogger(__name__)


class Source(threading.Thread):
    name_prefix = "source"

    def __init__(self, queue, stop_event):
        super().__init__(daemon=True, name=self.name_prefix)
        self.queue = queue
        self.stop_event = stop_event

    def emit(self, event):
        if event is not None:
            self.queue.put(event)


# ---------------------------------------------------------------------------
# Syslog (UDP + TCP, RFC 3164 / 5424, newline or octet-counted framing)
# ---------------------------------------------------------------------------

class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        peer = self.client_address[0]
        for line in data.decode("utf-8", errors="replace").splitlines() or [""]:
            self.server.source.emit(parse_syslog_line(line, channel=f"udp:{peer}", default_host=peer))


_OCTET_COUNT = re.compile(rb"^(\d{1,6}) ")


class _TCPHandler(socketserver.StreamRequestHandler):
    timeout = 300

    def handle(self):
        peer = self.client_address[0]
        buffer = b""
        while not self.server.source.stop_event.is_set():
            try:
                chunk = self.request.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk
            while buffer:
                counted = _OCTET_COUNT.match(buffer)
                if counted:  # RFC 6587 octet counting: "<len> <msg>"
                    length = int(counted.group(1))
                    start = counted.end()
                    if len(buffer) < start + length:
                        break
                    frame, buffer = buffer[start:start + length], buffer[start + length:]
                else:
                    newline = buffer.find(b"\n")
                    if newline < 0:
                        if len(buffer) > 1_000_000:
                            frame, buffer = buffer, b""
                        else:
                            break
                    else:
                        frame, buffer = buffer[:newline], buffer[newline + 1:]
                text = frame.decode("utf-8", errors="replace")
                if text.strip():
                    self.server.source.emit(parse_syslog_line(text, channel=f"tcp:{peer}", default_host=peer))
        if buffer.strip():
            self.server.source.emit(parse_syslog_line(buffer.decode("utf-8", errors="replace"), channel=f"tcp:{peer}", default_host=peer))


class _ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class SyslogSource(Source):
    name_prefix = "syslog"

    def __init__(self, queue, stop_event, *, host="0.0.0.0", port=5514, udp=True, tcp=True):
        super().__init__(queue, stop_event)
        self.servers = []
        try:
            if udp:
                self.servers.append(_ThreadingUDPServer((host, port), _UDPHandler))
            if tcp:
                self.servers.append(_ThreadingTCPServer((host, port), _TCPHandler))
        except OSError:
            for server in self.servers:
                server.server_close()
            raise
        for server in self.servers:
            server.source = self
        self.description = f"syslog {'UDP' if udp else ''}{'+' if udp and tcp else ''}{'TCP' if tcp else ''} on {host}:{port}"

    def run(self):
        threads = [threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True) for s in self.servers]
        for thread in threads:
            thread.start()
        self.stop_event.wait()
        for server in self.servers:
            server.shutdown()
            server.server_close()


# ---------------------------------------------------------------------------
# File tailing (handles growth, truncation and rotation; glob patterns allowed)
# ---------------------------------------------------------------------------

class _TailedFile:
    def __init__(self, path, from_start):
        self.path = path
        self.handle = None
        self.inode = None
        self.buffer = b""
        self.open(from_start)

    def open(self, from_start):
        if self.handle:
            self.handle.close()
        self.handle = open(self.path, "rb")
        stat = os.fstat(self.handle.fileno())
        self.inode = (stat.st_dev, stat.st_ino)
        if not from_start:
            self.handle.seek(0, os.SEEK_END)
        self.buffer = b""

    def rotated(self):
        try:
            stat = os.stat(self.path)
        except OSError:
            return False
        if (stat.st_dev, stat.st_ino) != self.inode:
            return True
        return stat.st_size < self.handle.tell()

    def read_lines(self):
        chunk = self.handle.read(1_048_576)
        if not chunk:
            return []
        self.buffer += chunk
        *lines, self.buffer = self.buffer.split(b"\n")
        return [line.decode("utf-8", errors="replace") for line in lines]

    def close(self):
        if self.handle:
            self.handle.close()


class FileTailSource(Source):
    name_prefix = "filetail"

    def __init__(self, queue, stop_event, *, patterns, from_start=False, poll_seconds=0.5, host=""):
        super().__init__(queue, stop_event)
        self.patterns = [str(Path(p).expanduser()) for p in patterns]
        self.from_start = from_start
        self.poll_seconds = poll_seconds
        self.host = host
        self.files = {}
        self.description = "files " + ", ".join(self.patterns)

    def _discover(self, first_pass):
        for pattern in self.patterns:
            for path in glob.glob(pattern) or ([pattern] if os.path.isfile(pattern) else []):
                if path in self.files or not os.path.isfile(path):
                    continue
                try:
                    # Files present at start-up are followed from their end (unless --from-start);
                    # files that appear later are read from the beginning.
                    self.files[path] = _TailedFile(path, from_start=self.from_start or not first_pass)
                    logger.info("Tailing %s", path)
                except OSError as exc:
                    logger.warning("Cannot open %s: %s", path, exc)

    def run(self):
        self._discover(first_pass=True)
        if not self.files:
            logger.warning("No files match %s yet; waiting for them to appear.", self.patterns)
        last_discover = time.monotonic()
        while not self.stop_event.is_set():
            got_data = False
            for path, tailed in list(self.files.items()):
                try:
                    lines = tailed.read_lines()
                    if not lines and tailed.rotated():
                        logger.info("%s was rotated or truncated; reopening", path)
                        tailed.open(from_start=True)
                        lines = tailed.read_lines()
                except OSError as exc:
                    logger.warning("Lost %s: %s", path, exc)
                    tailed.close()
                    del self.files[path]
                    continue
                for line in lines:
                    got_data = True
                    self.emit(parse_file_line(line, channel=path, default_host=self.host))
            if time.monotonic() - last_discover > 5:
                self._discover(first_pass=False)
                last_discover = time.monotonic()
            if not got_data:
                self.stop_event.wait(self.poll_seconds)
        for tailed in self.files.values():
            tailed.close()


# ---------------------------------------------------------------------------
# Windows Event Log (polls wevtutil, so no extra Python dependency is needed)
# ---------------------------------------------------------------------------

DEFAULT_WINDOWS_CHANNELS = (
    "Security",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
)

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _wevtutil(args, timeout=30):
    return subprocess.run(
        ["wevtutil", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=_NO_WINDOW,
    )


def _parse_events_xml(text):
    text = (text or "").strip()
    if not text:
        return []
    root = ElementTree.fromstring(text if text.startswith("<Events") else f"<Events>{text}</Events>")
    return list(root)


class WindowsEventLogSource(Source):
    name_prefix = "wineventlog"

    def __init__(self, queue, stop_event, *, channels=DEFAULT_WINDOWS_CHANNELS, poll_seconds=2.0, from_start=False, batch=500):
        super().__init__(queue, stop_event)
        self.channels = list(channels)
        self.poll_seconds = poll_seconds
        self.from_start = from_start
        self.batch = batch
        self.last_record = {}
        self.description = "Windows Event Log " + ", ".join(self.channels)

    @staticmethod
    def available():
        return sys.platform == "win32"

    def _latest_record_id(self, channel):
        result = _wevtutil(["qe", channel, "/c:1", "/rd:true", "/f:xml", "/e:Events"])
        if result.returncode != 0:
            raise PermissionError(result.stderr.strip() or result.stdout.strip() or f"wevtutil exit {result.returncode}")
        for element in _parse_events_xml(result.stdout):
            event = windows_event_from_element(element)
            if event and event.fields.get("record_id"):
                return int(event.fields["record_id"])
        return 0

    def _init_channels(self):
        for channel in list(self.channels):
            try:
                self.last_record[channel] = 0 if self.from_start else self._latest_record_id(channel)
                logger.info("Watching Windows log %s from record %s", channel, self.last_record[channel])
            except PermissionError as exc:
                hint = " (run as Administrator to read the Security log)" if "denied" in str(exc).lower() else ""
                logger.warning("Skipping Windows log %s: %s%s", channel, exc, hint)
                self.channels.remove(channel)
            except Exception as exc:
                logger.warning("Skipping Windows log %s: %s", channel, exc)
                self.channels.remove(channel)

    def poll_channel(self, channel):
        query = f"*[System[(EventRecordID>{self.last_record[channel]})]]"
        result = _wevtutil(["qe", channel, f"/q:{query}", f"/c:{self.batch}", "/f:xml", "/e:Events"])
        if result.returncode != 0:
            logger.warning("wevtutil failed for %s: %s", channel, result.stderr.strip())
            return 0
        count = 0
        for element in _parse_events_xml(result.stdout):
            event = windows_event_from_element(element)
            if event is None:
                continue
            record_id = int(event.fields.get("record_id") or 0)
            self.last_record[channel] = max(self.last_record[channel], record_id)
            self.emit(event)
            count += 1
        return count

    def run(self):
        self._init_channels()
        if not self.channels:
            logger.warning("No readable Windows event logs; Windows source stopped.")
            return
        while not self.stop_event.is_set():
            busy = False
            for channel in self.channels:
                try:
                    busy = self.poll_channel(channel) >= self.batch or busy
                except Exception:
                    logger.exception("Error reading Windows log %s", channel)
            if not busy:
                self.stop_event.wait(self.poll_seconds)
