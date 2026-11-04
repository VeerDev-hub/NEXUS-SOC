from datetime import datetime, timedelta

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.alerts.models import Alert, AlertAnalyticType
from apps.livedetect.baseline import (
    BaselineEngine,
    ProfileStore,
    extract_observations,
    usual_hours,
)
from apps.livedetect.engine import DetectionEngine, create_detection_alert
from apps.livedetect.events import LogEvent, parse_syslog_line
from apps.livedetect.models import EntityProfile


def local(day, hour, minute=0):
    return timezone.make_aware(datetime(2026, 10, day, hour, minute), timezone.get_current_timezone())


def ssh_ok(user="alice", ip="10.0.0.5", host="web-01", ts=None):
    event = parse_syslog_line(f"<38>Oct  1 10:00:00 {host} sshd[99]: Accepted publickey for {user} from {ip} port 50000 ssh2")
    event.timestamp = ts
    return event


def sudo(user="alice", host="web-01", ts=None, command="/usr/bin/apt update"):
    event = parse_syslog_line(f"<85>Oct  1 10:00:00 {host} sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}")
    event.timestamp = ts
    return event


def win_logon(user="bob", ip="10.0.0.8", host="WS-01", logon_type="10", ts=None):
    return LogEvent(source="windows", message="EventID 4624", host=host, event_id=4624, timestamp=ts,
                    fields={"target_user": user, "logon_type": logon_type, "src_ip": ip})


def win_process(process, host="WS-01", user="bob", ts=None):
    return LogEvent(source="windows", message="EventID 4688", host=host, event_id=4688, timestamp=ts,
                    fields={"process": process, "actor_user": user, "command": process})


def engine(**kwargs):
    defaults = dict(store=ProfileStore(persist=False), min_observations=5, min_age_hours=24, min_process_events=20)
    defaults.update(kwargs)
    return BaselineEngine(**defaults)


def train_logons(baseline, user="alice", ip="10.0.0.5", host="web-01", days=range(1, 8), hours=(9, 10, 11)):
    for day in days:
        for hour in hours:
            assert baseline.observe(ssh_ok(user, ip, host, ts=local(day, hour))) == []


class ObservationTests(SimpleTestCase):
    def test_extracts_ssh_logon_sudo_and_windows_events(self):
        (obs,) = extract_observations(ssh_ok(ts=local(1, 9)))
        self.assertEqual((obs.kind, obs.user, obs.src_ip, obs.host), ("logon", "alice", "10.0.0.5", "web-01"))
        (obs,) = extract_observations(sudo(ts=local(1, 9)))
        self.assertEqual((obs.kind, obs.user, obs.command), ("privilege", "alice", "/usr/bin/apt update"))
        (obs,) = extract_observations(win_logon(user="CORP\\Bob", ts=local(1, 9)))
        self.assertEqual((obs.user, obs.detail["logon_type"]), ("bob", "RDP"))
        (obs,) = extract_observations(win_process("C:\\Windows\\System32\\cmd.exe", ts=local(1, 9)))
        self.assertEqual(obs.process, "c:\\windows\\system32\\cmd.exe")

    def test_ignores_service_accounts_failed_sudo_and_service_logons(self):
        self.assertEqual(extract_observations(win_logon(user="WS-01$", ts=local(1, 9))), [])
        self.assertEqual(extract_observations(win_logon(user="SYSTEM", ts=local(1, 9))), [])
        self.assertEqual(extract_observations(win_logon(logon_type="5", ts=local(1, 9))), [])  # service logon
        failed = parse_syslog_line("<85>Oct  1 10:00:00 web-01 sudo:    eve : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh")
        self.assertEqual(extract_observations(failed), [])
        denied = parse_syslog_line("<85>Oct  1 10:00:00 web-01 sudo:    eve : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh")
        self.assertEqual(extract_observations(denied), [])

    def test_usual_hours_ranges(self):
        hours = [0] * 24
        for h in (9, 10, 11, 14):
            hours[h] = 10
        self.assertEqual(usual_hours(hours, coverage=1.0), "09:00-12:00, 14:00-15:00")


class BaselineEngineTests(SimpleTestCase):
    def test_no_alerts_while_learning(self):
        baseline = engine()
        train_logons(baseline, days=[1], hours=range(9, 15))  # 6 logons but < 24h of history
        self.assertEqual(baseline.observe(ssh_ok(ip="198.51.100.9", ts=local(1, 15))), [])

    def test_normal_logon_is_quiet(self):
        baseline = engine()
        train_logons(baseline)
        self.assertEqual(baseline.observe(ssh_ok(ts=local(8, 10, 30))), [])

    def test_new_external_ip_at_night_is_high(self):
        baseline = engine()
        train_logons(baseline)
        (anomaly,) = baseline.observe(ssh_ok(ip="185.220.101.4", ts=local(8, 3)))
        self.assertEqual(anomaly.rule.id, "ueba.anomalous_logon")
        self.assertEqual(anomaly.severity, "High")
        self.assertEqual(anomaly.score, 85)  # new IP 40 + first external 20 + unusual hour 25
        text = " ".join(anomaly.reasons)
        self.assertIn("first logon from source IP 185.220.101.4", text)
        self.assertIn("internal addresses", text)
        self.assertIn("outside the usual hours (09:00-12:00)", text)
        self.assertEqual(anomaly.fields["baseline"]["known_source_ips"], ["10.0.0.5"])
        # learned now: the same IP during work hours is no longer new
        self.assertEqual(baseline.observe(ssh_ok(ip="185.220.101.4", ts=local(8, 10))), [])

    def test_new_host_is_medium_and_hour_alone_is_below_alert_threshold(self):
        baseline = engine()
        train_logons(baseline)
        (anomaly,) = baseline.observe(ssh_ok(host="db-01", ts=local(8, 10)))
        self.assertEqual((anomaly.score, anomaly.severity), (30, "Low"))
        self.assertIn("first logon to host db-01", anomaly.reasons[0])
        self.assertEqual(baseline.observe(ssh_ok(ts=local(8, 2))), [])  # 25 < min score 30
        profile = baseline.store.peek("user", "alice")
        self.assertGreater(profile.risk_score, 0)

    def test_repeated_anomalies_escalate_entity_risk(self):
        baseline = engine()
        train_logons(baseline)
        first = baseline.observe(ssh_ok(ip="185.220.101.4", ts=local(8, 3)))[0]
        second = baseline.observe(ssh_ok(ip="45.83.64.1", host="db-01", ts=local(8, 3, 20)))[0]
        self.assertLess(first.fields["entity_risk"], second.fields["entity_risk"])
        self.assertEqual(second.fields["entity_risk"], 100)
        self.assertIn("risk score", second.reasons[-1])
        self.assertEqual(second.severity, "High")

    def test_first_sudo_use(self):
        baseline = engine()
        train_logons(baseline)
        (anomaly,) = baseline.observe(sudo(ts=local(8, 10)))
        self.assertEqual((anomaly.rule.id, anomaly.severity), ("ueba.first_privilege_use", "Medium"))
        self.assertEqual(baseline.observe(sudo(ts=local(8, 11))), [])  # now known
        (anomaly,) = baseline.observe(sudo(host="db-01", ts=local(8, 12)))
        self.assertIn("never on db-01", anomaly.reasons[0])
        # 35 points on top of the still-fresh first-sudo risk (~47) crosses 80: escalated
        self.assertEqual((anomaly.score, anomaly.severity), (70, "High"))

    def test_isolated_sudo_on_new_host_is_low(self):
        baseline = engine()
        train_logons(baseline)
        baseline.observe(sudo(ts=local(1, 10)))  # sudo a week ago: its risk has decayed by now
        (anomaly,) = baseline.observe(sudo(host="db-01", ts=local(8, 12)))
        self.assertEqual((anomaly.score, anomaly.severity), (35, "Low"))

    def test_rare_process_scoring_and_budget(self):
        baseline = engine(process_alerts_per_hour=2)
        for day in range(1, 4):
            for i in range(10):
                baseline.observe(win_process(f"C:\\Windows\\System32\\tool{i}.exe", ts=local(day, 10, i)))
        self.assertEqual(baseline.observe(win_process("C:\\Windows\\System32\\tool3.exe", ts=local(4, 10))), [])
        (anomaly,) = baseline.observe(win_process("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", ts=local(4, 11)))
        self.assertEqual((anomaly.rule.id, anomaly.score, anomaly.severity), ("ueba.rare_process", 60, "Medium"))
        self.assertEqual(anomaly.fields["process_name"], "x.exe")
        self.assertEqual(len(baseline.observe(win_process("C:\\Program Files\\New\\a.exe", ts=local(4, 11, 10)))), 1)
        # budget of 2 per hour reached: a plain new binary is learned silently
        self.assertEqual(baseline.observe(win_process("C:\\Program Files\\New\\b.exe", ts=local(4, 11, 20))), [])
        self.assertIn("c:\\program files\\new\\b.exe", baseline.store.peek("host", "ws-01").data["processes"])

    def test_learn_only_never_alerts(self):
        baseline = engine(learn_only=True)
        train_logons(baseline)
        self.assertEqual(baseline.observe(ssh_ok(ip="185.220.101.4", ts=local(8, 3))), [])
        self.assertEqual(baseline.store.peek("user", "alice").data["logons"], 22)


class BaselinePipelineTests(TestCase):
    def test_anomaly_becomes_behavioural_alert_once(self):
        emitted = []
        baseline = engine()
        detector = DetectionEngine(emit=emitted.append, baseline=baseline, cooldown_seconds=600)
        for day in range(1, 8):
            for hour in (9, 10, 11):
                detector.process(ssh_ok(ts=local(day, hour)))
        self.assertEqual(emitted, [])
        detector.process(ssh_ok(ip="185.220.101.4", ts=local(8, 3)))
        self.assertEqual(len(emitted), 1)
        detection = emitted[0]
        self.assertEqual(detection.title, "Anomalous logon for alice on web-01: new source 185.220.101.4, unusual hour")

        result = create_detection_alert(detection, schedule_analysis=False)
        alert = Alert.objects.get(pk=result.alert.pk)
        self.assertEqual(alert.analytic_type, AlertAnalyticType.BEHAVIORAL)
        self.assertEqual(alert.severity, "High")
        self.assertIn("Behavioural baseline deviation", alert.desc)
        self.assertIn("first logon from source IP 185.220.101.4", alert.desc)
        self.assertEqual(alert.rule_id, "ueba.anomalous_logon")

    def test_profiles_persist_and_reload(self):
        baseline = engine(store=ProfileStore())
        train_logons(baseline)
        self.assertEqual(baseline.flush(), 2)  # user alice + host web-01
        row = EntityProfile.objects.get(entity_type="user", entity="alice")
        self.assertEqual(row.data["logons"], 21)
        self.assertEqual(row.first_seen, local(1, 9))

        reloaded = engine(store=ProfileStore())
        (anomaly,) = reloaded.observe(ssh_ok(ip="185.220.101.4", ts=local(8, 3)))
        self.assertEqual(anomaly.severity, "High")
        reloaded.flush()
        row.refresh_from_db()
        self.assertEqual(row.anomaly_count, 1)
        self.assertEqual(row.last_anomaly["rule"], "ueba.anomalous_logon")

    def test_profile_api(self):
        from apps.accounts.models import User

        baseline = engine(store=ProfileStore())
        train_logons(baseline)
        baseline.observe(ssh_ok(ip="185.220.101.4", ts=local(8, 3)))
        baseline.flush()
        from rest_framework.test import APIClient

        client = APIClient()
        client.force_authenticate(User.objects.create_user(username="analyst", password="x-Password-123"))
        self.assertEqual(APIClient().get("/api/ueba/profiles/").status_code, 401)
        response = client.get("/api/ueba/profiles/?type=user")
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body["totals"]["users"], 1)
        item = body["results"][0]
        self.assertEqual((item["entity"], item["anomaly_count"]), ("alice", 1))
        detail = client.get(f"/api/ueba/profiles/{item['id']}/").json()
        self.assertEqual(detail["baseline"]["top_source_ips"][0]["value"], "10.0.0.5")
        self.assertEqual(sum(detail["baseline"]["hours"]), 22)
