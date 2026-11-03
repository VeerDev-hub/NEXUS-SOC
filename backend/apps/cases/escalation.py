"""Tier-1 -> Tier-2 escalation, used by analysts and by the AI agent team."""

from django.db import transaction
from django.utils import timezone

from apps.audit.context import audit_actor

from .models import Case, CaseStatus, CaseTier

CLOSED_STATUSES = {CaseStatus.RESOLVED, CaseStatus.CLOSED}
AUTO_ESCALATE_VERDICTS = {"True Positive"}
AUTO_ESCALATE_SEVERITIES = {"High", "Critical"}


@transaction.atomic
def escalate_case(case, *, user=None, reason=""):
    locked = Case.objects.select_for_update().get(pk=case.pk)
    if locked.tier == CaseTier.L2:
        return locked, False
    locked.tier = CaseTier.L2
    locked.escalated_at = timezone.now()
    locked.escalated_by = user if getattr(user, "is_authenticated", False) else None
    locked.escalation_reason = (reason or "").strip()[:2000]
    if locked.status == CaseStatus.NEW:
        locked.status = CaseStatus.IN_PROGRESS
    with audit_actor(locked.escalated_by):
        locked.save(update_fields=["tier", "escalated_at", "escalated_by", "escalation_reason", "status", "updated_at"])
    return locked, True


def maybe_auto_escalate(case, *, verdict, severity, summary=""):
    """Hand confirmed high-impact incidents from the AI team straight to Tier-2."""
    if verdict in AUTO_ESCALATE_VERDICTS and severity in AUTO_ESCALATE_SEVERITIES:
        reason = f"Confirmed {verdict} with {severity} severity."
        if summary:
            reason += f" {summary[:500]}"
        return escalate_case(case, reason=reason)
    return case, False
