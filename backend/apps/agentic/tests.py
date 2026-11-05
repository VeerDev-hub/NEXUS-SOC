from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from apps.agentic.models import ActionProposal, ActionProposalStatus, AgentRunStatus
from apps.agentic.multiagent import actions
from apps.agentic.multiagent.llm_gateway import MODE_AUTO, MODE_OFFLINE, MODE_ONLINE, LLMGateway, LLMResult
from apps.agentic.multiagent.orchestrator import Orchestrator
from apps.agentic.multiagent.schemas import SupervisorDecision, TriageResult
from apps.agentic.services.alerts import create_alert_with_context
from apps.alerts.models import Confidence, Severity
from apps.artifacts.models import ArtifactName, ArtifactRole, ArtifactType


def make_case(*, title="Potential Ransomware Activity on prod-web-01", labels=("ransomware",), severity=Severity.CRITICAL,
              confidence=Confidence.HIGH, desc="vssadmin.exe delete shadows /all /quiet", extra_artifacts=()):
    artifacts = [
        {"value": "prod-web-01", "type": ArtifactType.HOSTNAME, "role": ArtifactRole.AFFECTED, "name": ArtifactName.AFFECTED_HOST},
        {"value": "admin_jsmith", "type": ArtifactType.USER_NAME, "role": ArtifactRole.ACTOR, "name": ArtifactName.SOURCE_USER},
        {"value": "45.77.10.99", "type": ArtifactType.IP_ADDRESS, "role": ArtifactRole.RELATED, "name": ArtifactName.UNKNOWN},
        *extra_artifacts,
    ]
    result = create_alert_with_context(
        case_defaults={"title": title, "correlation_uid": f"test-{title}"},
        alert_fields={
            "title": title, "severity": severity, "confidence": confidence, "desc": desc,
            "labels": list(labels), "rule_name": "EDR Vssadmin Delete Shadows",
            "technique": "T1490 - Inhibit System Recovery", "tactic": "Impact",
        },
        artifacts=artifacts,
        enrichments=[],
        schedule_analysis=False,
    )
    return result.case


@mock.patch("apps.agentic.multiagent.events._emit", lambda *a, **k: None)
class OfflineOrchestrationTests(TestCase):
    def test_full_offline_run_reaches_report_and_proposes_actions(self):
        case = make_case()
        run = Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE)).run(case, trigger="test")

        self.assertEqual(run.status, AgentRunStatus.COMPLETED)
        self.assertEqual(run.llm_mode, "offline")
        agents = list(run.steps.exclude(agent="supervisor").values_list("agent", flat=True))
        self.assertEqual(agents[0], "triage")
        self.assertEqual(agents[-1], "reporting")
        self.assertIn("investigation", agents)
        self.assertIn("response", agents)
        self.assertEqual(run.final_verdict, "True Positive")

        case.refresh_from_db()
        self.assertEqual(case.verdict_ai, "True Positive")
        self.assertTrue(case.investigation_report_ai_json)

        isolate = ActionProposal.objects.get(case=case, action_type="isolate_host")
        self.assertEqual(isolate.status, ActionProposalStatus.PENDING)
        ticket = ActionProposal.objects.get(case=case, action_type="create_ticket")
        self.assertEqual(ticket.status, ActionProposalStatus.EXECUTED)
        self.assertTrue(ticket.auto_approved)

    def test_confident_false_positive_skips_investigation(self):
        case = make_case(
            title="Authorized pentest scanner activity",
            labels=("pentest",),
            severity=Severity.LOW,
            desc="Scheduled authorized scan",
        )
        run = Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE)).run(case, trigger="test")
        agents = list(run.steps.exclude(agent="supervisor").values_list("agent", flat=True))
        self.assertEqual(agents, ["triage", "reporting"])
        self.assertEqual(run.final_verdict, "False Positive")
        self.assertFalse(ActionProposal.objects.filter(case=case).exists())

    def test_rerun_does_not_duplicate_proposals(self):
        case = make_case()
        orchestrator = Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE))
        orchestrator.run(case)
        count = ActionProposal.objects.filter(case=case).count()
        Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE)).run(case)
        self.assertEqual(ActionProposal.objects.filter(case=case).count(), count)


class GatewayTests(TestCase):
    CONFIG = {"name": "DeepSeek test", "provider": "deepseek", "base_url": "http://127.0.0.1:9", "model": "deepseek-chat", "api_key": "x", "tags": []}

    def _offline(self):
        return TriageResult(classification="x", verdict="Suspicious", severity="Low", priority="Low", confidence_score=10, summary="offline")

    def test_auto_mode_falls_back_when_provider_unreachable(self):
        gateway = LLMGateway(mode=MODE_AUTO, configs=[self.CONFIG])
        result = gateway.invoke(agent_key="triage", system_prompt="", payload={}, schema=TriageResult, offline_fn=self._offline)
        self.assertEqual(result.mode, "offline")
        self.assertIn("unreachable", result.fallback_reason)

    def test_auto_mode_falls_back_when_call_errors(self):
        gateway = LLMGateway(mode=MODE_AUTO, configs=[self.CONFIG])
        with mock.patch("apps.agentic.multiagent.llm_gateway.probe_endpoint", return_value=(True, "ok")), \
                mock.patch.object(LLMGateway, "_call", side_effect=RuntimeError("401 invalid key")):
            result = gateway.invoke(agent_key="triage", system_prompt="", payload={}, schema=TriageResult, offline_fn=self._offline)
        self.assertEqual(result.mode, "offline")
        self.assertIn("401", result.fallback_reason)

    def test_online_mode_uses_provider_and_records_usage(self):
        gateway = LLMGateway(mode=MODE_ONLINE, configs=[self.CONFIG])
        online = self._offline().model_copy(update={"summary": "from llm"})
        with mock.patch.object(LLMGateway, "_call", return_value=(online, 120, 40)):
            result = gateway.invoke(agent_key="triage", system_prompt="", payload={}, schema=TriageResult, offline_fn=self._offline)
        self.assertEqual(result.mode, "online")
        self.assertEqual(result.output.summary, "from llm")
        self.assertEqual((result.tokens_in, result.tokens_out), (120, 40))
        self.assertEqual(result.provider, "DeepSeek test")

    def test_online_mode_propagates_errors(self):
        gateway = LLMGateway(mode=MODE_ONLINE, configs=[self.CONFIG])
        with mock.patch.object(LLMGateway, "_call", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                gateway.invoke(agent_key="triage", system_prompt="", payload={}, schema=TriageResult, offline_fn=self._offline)


class _ScriptedGateway(LLMGateway):
    """Online-looking gateway whose Supervisor always asks for an illegal agent."""

    def __init__(self):
        super().__init__(mode=MODE_OFFLINE)

    def invoke(self, *, agent_key, schema, offline_fn, **kwargs):
        if schema is SupervisorDecision:
            return LLMResult(output=SupervisorDecision(next_agent="response", reasoning="jump ahead"), mode="online")
        return super().invoke(agent_key=agent_key, schema=schema, offline_fn=offline_fn, **kwargs)


@mock.patch("apps.agentic.multiagent.events._emit", lambda *a, **k: None)
class SupervisorGuardrailTests(TestCase):
    def test_illegal_llm_route_is_overridden_by_policy(self):
        case = make_case()
        run = Orchestrator(gateway=_ScriptedGateway()).run(case)
        overridden = run.steps.filter(agent="supervisor", output__overridden=True)
        self.assertTrue(overridden.exists())
        self.assertIn("Guardrail override", overridden.first().routing_reason)
        agents = list(run.steps.exclude(agent="supervisor").values_list("agent", flat=True))
        self.assertLess(agents.index("investigation"), agents.index("response"))


class ApprovalPolicyTests(TestCase):
    def test_risk_tiers_and_role_hierarchy(self):
        self.assertEqual(actions.assess_risk("create_ticket"), "Low")
        self.assertEqual(actions.assess_risk("isolate_host"), "High")
        self.assertEqual(actions.assess_risk("isolate_host", target_criticality="Critical"), "Critical")
        critical = SimpleNamespace(required_role=actions.required_role_for("Critical"))
        high = SimpleNamespace(required_role=actions.required_role_for("High"))
        self.assertFalse(actions.can_approve("tier2_responder", critical))
        self.assertTrue(actions.can_approve("soc_manager", critical))
        self.assertTrue(actions.can_approve("tier2_responder", high))
        self.assertFalse(actions.can_approve("tier1_analyst", high))
        self.assertFalse(actions.can_approve("auditor", high))
        self.assertTrue(actions.can_approve("admin", critical))


class EventPayloadTests(TestCase):
    def test_proposal_event_payload_is_channel_layer_safe(self):
        """Regression: UUID primary keys in serializer output broke msgpack encoding."""
        import msgpack

        from apps.agentic.multiagent import events

        case = make_case()
        proposal, _ = actions.create_proposal(case=case, run=None, step=None, action_type="block_ip", target="45.77.10.99", rationale="t")
        sent = []
        with mock.patch("apps.agentic.multiagent.events._send_group", lambda group, event: sent.append(event)):
            events.proposal_event("agent.proposal.created", proposal)
        self.assertEqual(len(sent), 1)
        msgpack.packb(sent[0])  # raises TypeError if anything is not encodable

    def test_emit_failure_does_not_raise(self):
        from apps.agentic.multiagent import events

        with mock.patch("apps.agentic.multiagent.events._send_group", side_effect=RuntimeError("redis down")):
            events._emit("agent.run.started", {"x": 1})


@mock.patch("apps.agentic.multiagent.events._emit", lambda *a, **k: None)
class ResponseTargetingTests(TestCase):
    """Regression: the offline Response Agent must act on the right kind of entity."""

    def _actions(self, key):
        from apps.agentic import demo

        case = demo.launch(key)
        Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE)).run(case)
        return set(ActionProposal.objects.filter(case=case).values_list("action_type", "target"))

    def test_phishing_blocks_domain_instead_of_isolating_it(self):
        actions = self._actions("phishing")
        self.assertNotIn(("isolate_host", "micros0ft-secure-login.com"), actions)
        self.assertIn(("block_domain", "micros0ft-secure-login.com"), actions)
        self.assertIn(("block_sender", "it-support@micros0ft-secure-login.com"), actions)

    def test_cloud_escalation_targets_principal_not_account_id(self):
        actions = self._actions("cloud_privesc")
        targets = {t for _, t in actions}
        self.assertFalse(any(t.isdigit() for t in targets), targets)
        self.assertEqual(len([a for a in actions if a[0] == "revoke_iam_policy"]), 1)

    def test_suspicious_powershell_gets_no_disruptive_action(self):
        types = {a for a, _ in self._actions("encoded_powershell")}
        self.assertFalse(types & {"isolate_host", "disable_user", "reset_credentials"}, types)


@mock.patch("apps.agentic.multiagent.events._emit", lambda *a, **k: None)
class AutoMitigationTests(TestCase):
    def _propose(self, action_type, target, **kw):
        return actions.create_proposal(case=make_case(), run=None, step=None, action_type=action_type, target=target, rationale="t", **kw)[0]

    def test_low_severity_case_blocks_ip_automatically(self):
        for severity in ("Low", "Medium"):
            proposal = self._propose("block_ip", "45.77.10.99", case_severity=severity)
            self.assertEqual(proposal.status, ActionProposalStatus.EXECUTED, severity)
            self.assertTrue(proposal.auto_approved)
            self.assertIn("Auto-mitigated", proposal.decision_note)

    def test_high_severity_case_waits_for_human(self):
        for severity in ("High", "Critical", "", None):
            proposal = self._propose("block_ip", "45.77.10.99", case_severity=severity)
            self.assertEqual(proposal.status, ActionProposalStatus.PENDING, severity)

    def test_disruptive_or_critical_asset_actions_still_need_approval(self):
        self.assertEqual(self._propose("isolate_host", "ws-12", case_severity="Low").status, ActionProposalStatus.PENDING)
        self.assertEqual(self._propose("reset_credentials", "jdoe", case_severity="Low").status, ActionProposalStatus.PENDING)
        bumped = self._propose("block_ip", "10.0.0.5", case_severity="Low", target_criticality="Critical")
        self.assertEqual(bumped.status, ActionProposalStatus.PENDING)

    def test_can_be_switched_off(self):
        with self.settings(AGENT_AUTO_MITIGATE_ENABLED=False):
            self.assertEqual(self._propose("block_ip", "45.77.10.99", case_severity="Low").status, ActionProposalStatus.PENDING)


@mock.patch("apps.agentic.multiagent.events._emit", lambda *a, **k: None)
class SshBruteForceScenarioTests(TestCase):
    def test_medium_scan_is_auto_blocked_without_approval(self):
        from apps.agentic import demo

        case = demo.SCENARIOS["ssh_bruteforce"]["fn"]()
        run = Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE), pace_ms=0).run(case, trigger="alert_created")
        self.assertEqual(run.status, AgentRunStatus.COMPLETED)
        self.assertIn(run.final_severity, ("Low", "Medium"))
        block = ActionProposal.objects.get(case=case, action_type="block_ip")
        self.assertEqual(block.status, ActionProposalStatus.EXECUTED)
        self.assertTrue(block.auto_approved)
        self.assertFalse(ActionProposal.objects.filter(case=case, status=ActionProposalStatus.PENDING).exists())
