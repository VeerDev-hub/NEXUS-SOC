from types import SimpleNamespace
from unittest import mock

from django.core import mail
from django.test import TestCase, override_settings

from apps.agentic.multiagent.llm_gateway import MODE_OFFLINE, LLMGateway
from apps.agentic.multiagent.orchestrator import Orchestrator
from apps.agentic.tests import make_case
from apps.notifications.models import NotificationLog, NotificationStatus
from apps.notifications.service import notify_case_verdict, should_notify

EMAIL_SETTINGS = dict(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    ALERT_EMAIL_ENABLED=True,
    ALERT_EMAIL_TO=["soc@example.com", "lead@example.com"],
    ALERT_EMAIL_MIN_SEVERITY="High",
    ALERT_EMAIL_VERDICTS=["True Positive", "Suspicious"],
    SOC_CONSOLE_URL="http://soc.local",
)


def fake_run(case, verdict="True Positive", severity="Critical"):
    return SimpleNamespace(
        case=case,
        final_verdict=verdict,
        final_severity=severity,
        summary="Ransomware precursor confirmed.",
        report={
            "confidence": "High",
            "affected_assets": [{"asset_type": "host", "asset_value": "prod-web-01"}],
            "ioc_indicators": [{"indicator_type": "ip", "value": "45.77.10.99", "context": "C2"}],
            "remediations": [{"action_type": "isolate_host", "description": "prod-web-01: stop encryption"}],
        },
    )


@override_settings(**EMAIL_SETTINGS)
class NotificationTests(TestCase):
    def test_policy(self):
        self.assertTrue(should_notify("True Positive", "High"))
        self.assertTrue(should_notify("Suspicious", "Critical"))
        self.assertFalse(should_notify("True Positive", "Medium"))
        self.assertFalse(should_notify("False Positive", "Critical"))

    def test_sends_rich_email_once(self):
        case = make_case()
        log = notify_case_verdict(fake_run(case))
        self.assertEqual(log.status, NotificationStatus.SENT)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ["soc@example.com", "lead@example.com"])
        self.assertIn("[NEXUS-SOC][Critical] True Positive", message.subject)
        for expected in ("45.77.10.99", "isolate_host", f"http://soc.local/cases/{case.pk}", "T1490"):
            self.assertIn(expected, message.body)
        html = message.alternatives[0][0]
        self.assertIn("Open case in NEXUS-SOC", html)

        # Re-analysis with the same verdict does not spam; an upgrade in severity does.
        self.assertIsNone(notify_case_verdict(fake_run(case, severity="High")))
        self.assertIsNone(notify_case_verdict(fake_run(case, severity="Critical")))
        self.assertEqual(len(mail.outbox), 1)
        notify_case_verdict(fake_run(case, verdict="Suspicious", severity="High"))
        self.assertEqual(len(mail.outbox), 2)

    def test_html_is_escaped(self):
        case = make_case(title="<script>alert(1)</script> on host")
        notify_case_verdict(fake_run(case))
        html = mail.outbox[0].alternatives[0][0]
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_low_severity_and_benign_are_not_emailed(self):
        case = make_case()
        self.assertIsNone(notify_case_verdict(fake_run(case, severity="Medium")))
        self.assertIsNone(notify_case_verdict(fake_run(case, verdict="False Positive")))
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(ALERT_EMAIL_TO=[])
    def test_no_recipients_means_no_email(self):
        self.assertIsNone(notify_case_verdict(fake_run(make_case())))
        self.assertEqual(NotificationLog.objects.count(), 0)

    def test_smtp_failure_is_logged_not_raised(self):
        case = make_case()
        with mock.patch("apps.notifications.service.EmailMultiAlternatives.send", side_effect=OSError("connection refused")):
            log = notify_case_verdict(fake_run(case))
        self.assertEqual(log.status, NotificationStatus.FAILED)
        self.assertIn("connection refused", log.error)
        # A failed attempt does not block a later retry.
        self.assertEqual(notify_case_verdict(fake_run(case)).status, NotificationStatus.SENT)

    @mock.patch("apps.agentic.multiagent.events._emit", lambda *a, **k: None)
    def test_agent_run_completion_sends_email(self):
        case = make_case()
        run = Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE)).run(case, trigger="test")
        self.assertEqual(run.final_verdict, "True Positive")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(NotificationLog.objects.get().agent_run_id, run.pk)
