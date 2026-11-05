"""Response action catalogue, approval policy and (simulated) execution.

Safety design: the Response Agent may only *propose* actions from this fixed
catalogue. The risk tier of each action is decided here by policy, not by the
LLM, and is raised one level when the target is a business-critical asset.

    Low      -> auto-approved and executed by policy (logged as such)
    Medium   -> also auto-executed when the *case* is low severity (Low/Medium by
                default) and the action is on AGENT_AUTO_MITIGATE_ACTIONS
    Medium   -> needs a Tier-2 Incident Responder (or Manager/Admin)
    High     -> needs a Tier-2 Incident Responder (or Manager/Admin)
    Critical -> needs a SOC Manager (or Admin)

Execution is simulated: no real firewall/EDR/IdP is touched. Each connector
returns a realistic result payload so the workflow is demonstrable end to end.
"""

import logging
import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.agentic.models import ActionProposal, ActionProposalStatus, ActionRiskLevel

logger = logging.getLogger(__name__)

ROLE_TIER2 = "tier2_responder"
ROLE_MANAGER = "soc_manager"
ROLE_ADMIN = "admin"

RISK_ORDER = [ActionRiskLevel.LOW, ActionRiskLevel.MEDIUM, ActionRiskLevel.HIGH, ActionRiskLevel.CRITICAL]

ACTION_CATALOG = {
    "create_ticket": {"label": "Open ticket & notify owner", "risk": ActionRiskLevel.LOW, "connector": "ITSM"},
    "block_sender": {"label": "Block email sender", "risk": ActionRiskLevel.LOW, "connector": "Email Gateway"},
    "quarantine_file": {"label": "Quarantine file hash", "risk": ActionRiskLevel.LOW, "connector": "EDR"},
    "block_ip": {"label": "Block IP at perimeter firewall", "risk": ActionRiskLevel.MEDIUM, "connector": "Firewall"},
    "block_domain": {"label": "Block domain / URL at proxy & DNS", "risk": ActionRiskLevel.MEDIUM, "connector": "Secure Web Gateway"},
    "purge_email": {"label": "Purge email from all mailboxes", "risk": ActionRiskLevel.MEDIUM, "connector": "Email Gateway"},
    "reset_credentials": {"label": "Force password reset", "risk": ActionRiskLevel.MEDIUM, "connector": "Identity Provider"},
    "revoke_sessions": {"label": "Revoke active sessions & tokens", "risk": ActionRiskLevel.MEDIUM, "connector": "Identity Provider"},
    "isolate_host": {"label": "Network-isolate host", "risk": ActionRiskLevel.HIGH, "connector": "EDR"},
    "disable_user": {"label": "Disable user account", "risk": ActionRiskLevel.HIGH, "connector": "Identity Provider"},
    "revoke_iam_policy": {"label": "Detach IAM policy / revoke cloud permission", "risk": ActionRiskLevel.HIGH, "connector": "Cloud IAM"},
}


def catalog():
    return [{"action_type": key, **{k: str(v) for k, v in spec.items()}} for key, spec in ACTION_CATALOG.items()]


def assess_risk(action_type, *, target_criticality=None):
    base = ACTION_CATALOG.get(action_type, {}).get("risk", ActionRiskLevel.HIGH)
    if target_criticality == "Critical" and base != ActionRiskLevel.CRITICAL:
        return RISK_ORDER[RISK_ORDER.index(base) + 1]
    return base


def required_role_for(risk_level):
    if risk_level == ActionRiskLevel.LOW:
        return ""
    if risk_level == ActionRiskLevel.CRITICAL:
        return ROLE_MANAGER
    return ROLE_TIER2


CASE_SEVERITY_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def auto_mitigation_reason(action_type, risk_level, case_severity):
    """Why this action may run without a human, or '' if it must wait for approval."""
    if risk_level == ActionRiskLevel.LOW:
        return "Auto-approved by policy (low-risk action)."
    if not getattr(settings, "AGENT_AUTO_MITIGATE_ENABLED", False):
        return ""
    # Only Medium-risk actions qualify: a critical-asset bump to High always needs a human.
    if risk_level != ActionRiskLevel.MEDIUM or action_type not in getattr(settings, "AGENT_AUTO_MITIGATE_ACTIONS", ()):
        return ""
    limit = CASE_SEVERITY_RANK.get(getattr(settings, "AGENT_AUTO_MITIGATE_MAX_SEVERITY", "Medium"), 2)
    rank = CASE_SEVERITY_RANK.get(case_severity or "")
    if rank is None or rank > limit:
        return ""
    return f"Auto-mitigated by policy: {case_severity}-severity case, '{action_type}' is on the auto-mitigation list."


def can_approve(user_role, proposal):
    """Role hierarchy for approvals."""
    if user_role == ROLE_ADMIN:
        return True
    if proposal.required_role == ROLE_MANAGER:
        return user_role == ROLE_MANAGER
    if proposal.required_role == ROLE_TIER2:
        return user_role in (ROLE_TIER2, ROLE_MANAGER)
    return user_role in (ROLE_TIER2, ROLE_MANAGER)


def _simulate(proposal):
    spec = ACTION_CATALOG.get(proposal.action_type, {})
    return {
        "connector": spec.get("connector", "Generic"),
        "operation": spec.get("label", proposal.action_type),
        "target": proposal.target,
        "simulated": True,
        "reference": f"SIM-{uuid.uuid4().hex[:10].upper()}",
        "message": f"{spec.get('label', proposal.action_type)} completed for {proposal.target} (simulated connector).",
    }


@transaction.atomic
def execute_proposal(proposal):
    locked = ActionProposal.objects.select_for_update().get(pk=proposal.pk)
    if locked.status != ActionProposalStatus.APPROVED:
        raise ValueError("Only approved actions can be executed.")
    try:
        locked.execution_result = _simulate(locked)
        locked.status = ActionProposalStatus.EXECUTED
    except Exception as exc:
        logger.exception("Action execution failed: %s", locked)
        locked.execution_result = {"error": str(exc)}
        locked.status = ActionProposalStatus.FAILED
    locked.executed_at = timezone.now()
    locked.save(update_fields=["execution_result", "status", "executed_at", "updated_at"])
    return locked


@transaction.atomic
def decide_proposal(proposal, *, user, approve, note=""):
    locked = ActionProposal.objects.select_for_update().get(pk=proposal.pk)
    if locked.status != ActionProposalStatus.PENDING:
        raise ValueError(f"Action is already {locked.status}.")
    locked.status = ActionProposalStatus.APPROVED if approve else ActionProposalStatus.REJECTED
    locked.decided_by = user
    locked.decided_at = timezone.now()
    locked.decision_note = note or ""
    locked.save(update_fields=["status", "decided_by", "decided_at", "decision_note", "updated_at"])
    if approve:
        locked = execute_proposal(locked)
    return locked


def create_proposal(*, case, run, step, action_type, target, rationale, target_criticality=None, case_severity=None):
    risk = assess_risk(action_type, target_criticality=target_criticality)
    proposal, created = ActionProposal.objects.get_or_create(
        case=case,
        action_type=action_type,
        target=target[:500],
        defaults={
            "run": run,
            "step": step,
            "rationale": rationale,
            "risk_level": risk,
            "required_role": required_role_for(risk),
        },
    )
    auto_reason = auto_mitigation_reason(action_type, risk, case_severity) if created else ""
    if auto_reason:
        proposal.status = ActionProposalStatus.APPROVED
        proposal.auto_approved = True
        proposal.decided_at = timezone.now()
        proposal.decision_note = auto_reason
        proposal.save(update_fields=["status", "auto_approved", "decided_at", "decision_note", "updated_at"])
        proposal = execute_proposal(proposal)
    return proposal, created
