from unittest import mock

from django.test import TestCase
from rest_framework.test import APIClient

from apps.accounts import rbac
from apps.accounts.models import User
from apps.accounts.rbac import Role
from apps.agentic.models import ActionProposal
from apps.agentic.multiagent.actions import create_proposal
from apps.agentic.multiagent.llm_gateway import MODE_OFFLINE, LLMGateway
from apps.agentic.multiagent.orchestrator import Orchestrator
from apps.agentic.tests import make_case
from apps.cases.models import Case, CaseTier


def make_user(role, username=None):
    user = User.objects.create_user(username=username or role, password="x-test-pass-1", role=role)
    if role == Role.ADMIN:
        user.is_superuser = True
        user.save()
    return user


class RBACMatrixTests(TestCase):
    def test_superuser_is_always_admin(self):
        user = User.objects.create_superuser("root", "root@x.io", "pw-123456789")
        self.assertEqual(user.role, Role.ADMIN)
        self.assertTrue(rbac.has_perm(user, rbac.SETTINGS_MANAGE))

    def test_matrix_highlights(self):
        auditor, tier1, tier2, manager = (make_user(r) for r in (Role.AUDITOR, Role.TIER1_ANALYST, Role.TIER2_RESPONDER, Role.SOC_MANAGER))
        self.assertFalse(rbac.has_perm(auditor, rbac.RECORDS_WRITE))
        self.assertTrue(rbac.has_perm(auditor, rbac.AUDIT_VIEW))
        self.assertTrue(rbac.has_perm(tier1, rbac.CASES_ESCALATE))
        self.assertFalse(rbac.has_perm(tier1, rbac.CASES_CLOSE))
        self.assertTrue(rbac.has_perm(tier2, rbac.ACTIONS_APPROVE))
        self.assertTrue(rbac.has_perm(manager, rbac.DASHBOARD_TEAM))
        self.assertFalse(rbac.has_perm(manager, rbac.SETTINGS_MANAGE))

    def test_legacy_group_roles_are_not_used(self):
        tier2 = make_user(Role.TIER2_RESPONDER)
        self.assertEqual(rbac.role_of(tier2), "tier2_responder")


@mock.patch("apps.agentic.multiagent.events._emit", lambda *a, **k: None)
class RBACEndpointTests(TestCase):
    def setUp(self):
        self.users = {role: make_user(role) for role in Role}
        self.case = make_case()

    def client_for(self, role):
        client = APIClient()
        client.force_authenticate(self.users[role])
        return client

    def test_me_exposes_role_and_permissions(self):
        data = self.client_for(Role.TIER1_ANALYST).get("/api/auth/me/").data
        self.assertEqual(data["role"], "tier1_analyst")
        self.assertEqual(data["role_label"], "Tier-1 Analyst")
        self.assertIn("cases.escalate", data["permissions"])
        self.assertNotIn("cases.close", data["permissions"])

    def test_roles_catalogue(self):
        data = self.client_for(Role.AUDITOR).get("/api/auth/roles/").data
        self.assertEqual([r["value"] for r in data], [r.value for r in Role])

    def test_auditor_is_read_only(self):
        client = self.client_for(Role.AUDITOR)
        self.assertEqual(client.get(f"/api/cases/{self.case.pk}/").status_code, 200)
        self.assertEqual(client.patch(f"/api/cases/{self.case.pk}/", {"title": "x"}, format="json").status_code, 403)
        self.assertEqual(client.post(f"/api/cases/{self.case.pk}/agent-runs/", {}, format="json").status_code, 403)
        self.assertEqual(client.get("/api/settings/audit-logs/").status_code, 200)

    def test_tier1_can_escalate_but_not_close_or_delete(self):
        client = self.client_for(Role.TIER1_ANALYST)
        self.assertEqual(client.patch(f"/api/cases/{self.case.pk}/", {"status": "Closed"}, format="json").status_code, 403)
        self.assertEqual(client.delete(f"/api/cases/{self.case.pk}/").status_code, 403)
        self.assertEqual(client.get("/api/settings/audit-logs/").status_code, 403)
        response = client.post(f"/api/cases/{self.case.pk}/escalate/", {"reason": "Looks real"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["tier"], "L2")
        self.assertEqual(response.data["escalated_by_name"], "tier1_analyst")
        self.assertEqual(client.post(f"/api/cases/{self.case.pk}/escalate/", {}, format="json").status_code, 409)

    def test_tier2_can_close(self):
        client = self.client_for(Role.TIER2_RESPONDER)
        response = client.patch(f"/api/cases/{self.case.pk}/", {"status": "Resolved"}, format="json")
        self.assertEqual(response.status_code, 200)

    def test_knowledge_writes_need_tier2(self):
        body = {"title": "Whitelist", "body": "Scanner 10.0.0.5 is authorized."}
        self.assertEqual(self.client_for(Role.TIER1_ANALYST).post("/api/knowledge/", body, format="json").status_code, 403)
        self.assertEqual(self.client_for(Role.TIER2_RESPONDER).post("/api/knowledge/", body, format="json").status_code, 201)

    def test_settings_admin_only(self):
        self.assertEqual(self.client_for(Role.SOC_MANAGER).get("/api/settings/runtime/").status_code, 403)
        self.assertEqual(self.client_for(Role.ADMIN).get("/api/settings/runtime/").status_code, 200)

    def test_action_approval_tiers(self):
        high, _ = create_proposal(case=self.case, run=None, step=None, action_type="disable_user", target="admin_jsmith", rationale="t")
        critical, _ = create_proposal(case=self.case, run=None, step=None, action_type="isolate_host", target="prod-web-01",
                                      rationale="t", target_criticality="Critical")
        decide = lambda role, p: self.client_for(role).post(f"/api/action-proposals/{p.pk}/decide/", {"approve": True}, format="json")

        self.assertEqual(decide(Role.TIER1_ANALYST, high).status_code, 403)
        self.assertEqual(decide(Role.AUDITOR, high).status_code, 403)
        self.assertEqual(decide(Role.TIER2_RESPONDER, critical).status_code, 403)
        response = decide(Role.TIER2_RESPONDER, high)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "Executed")
        self.assertEqual(decide(Role.SOC_MANAGER, critical).status_code, 200)
        self.assertEqual(ActionProposal.objects.get(pk=critical.pk).decided_by, self.users[Role.SOC_MANAGER])


@mock.patch("apps.agentic.multiagent.events._emit", lambda *a, **k: None)
class AutoEscalationTests(TestCase):
    def test_confirmed_critical_incident_goes_to_tier2(self):
        case = make_case()
        Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE)).run(case)
        case = Case.objects.get(pk=case.pk)
        self.assertEqual(case.tier, CaseTier.L2)
        self.assertIsNone(case.escalated_by)
        self.assertIn("Confirmed True Positive", case.escalation_reason)

    def test_false_positive_stays_in_tier1(self):
        case = make_case(title="Authorized pentest scanner activity", labels=("pentest",), severity="Low", desc="authorized scan")
        Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE)).run(case)
        self.assertEqual(Case.objects.get(pk=case.pk).tier, CaseTier.L1)
