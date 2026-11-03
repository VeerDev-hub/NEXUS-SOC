"""Role-based access control: the single source of truth for who can do what.

The frontend receives ``permissions_for(user)`` from ``/api/auth/me/`` and uses it
to build menus and hide buttons; every API endpoint enforces the same matrix.
"""

from django.db import models


class Role(models.TextChoices):
    ADMIN = "admin", "SOC Admin"
    SOC_MANAGER = "soc_manager", "SOC Manager"
    TIER1_ANALYST = "tier1_analyst", "Tier-1 Analyst"
    TIER2_RESPONDER = "tier2_responder", "Tier-2 Incident Responder"
    AUDITOR = "auditor", "Auditor"


ROLE_DESCRIPTIONS = {
    Role.ADMIN: "Manages users, roles, LLM providers, integrations and agent configuration.",
    Role.SOC_MANAGER: "Oversees KPIs and team workload, approves critical response actions, owns reporting.",
    Role.TIER1_ANALYST: "Works the alert queue, reviews AI triage, escalates real incidents to Tier-2.",
    Role.TIER2_RESPONDER: "Investigates escalated cases, approves containment actions, closes incidents.",
    Role.AUDITOR: "Read-only access to cases, agent decision trails, reports and the audit log.",
}

# ---- permission keys ---------------------------------------------------------
DASHBOARD_VIEW = "dashboard.view"
DASHBOARD_TEAM = "dashboard.team"
RECORDS_VIEW = "records.view"
RECORDS_WRITE = "records.write"
RECORDS_DELETE = "records.delete"
CASES_ESCALATE = "cases.escalate"
CASES_CLOSE = "cases.close"
AGENTS_VIEW = "agents.view"
AGENTS_RUN = "agents.run"
ACTIONS_VIEW = "actions.view"
ACTIONS_APPROVE = "actions.approve"
KNOWLEDGE_WRITE = "knowledge.write"
REPORTS_VIEW = "reports.view"
AUDIT_VIEW = "audit.view"
SETTINGS_MANAGE = "settings.manage"
USERS_MANAGE = "users.manage"

ALL_PERMISSIONS = (
    DASHBOARD_VIEW, DASHBOARD_TEAM, RECORDS_VIEW, RECORDS_WRITE, RECORDS_DELETE, CASES_ESCALATE, CASES_CLOSE,
    AGENTS_VIEW, AGENTS_RUN, ACTIONS_VIEW, ACTIONS_APPROVE, KNOWLEDGE_WRITE, REPORTS_VIEW, AUDIT_VIEW,
    SETTINGS_MANAGE, USERS_MANAGE,
)

_READ_ONLY = {DASHBOARD_VIEW, RECORDS_VIEW, AGENTS_VIEW, ACTIONS_VIEW, REPORTS_VIEW}
_ANALYST = _READ_ONLY | {RECORDS_WRITE, CASES_ESCALATE, AGENTS_RUN}

ROLE_PERMISSIONS = {
    Role.ADMIN: set(ALL_PERMISSIONS),
    Role.SOC_MANAGER: _ANALYST | {
        DASHBOARD_TEAM, RECORDS_DELETE, CASES_CLOSE, ACTIONS_APPROVE, KNOWLEDGE_WRITE, AUDIT_VIEW,
    },
    Role.TIER2_RESPONDER: _ANALYST | {CASES_CLOSE, ACTIONS_APPROVE, KNOWLEDGE_WRITE},
    Role.TIER1_ANALYST: set(_ANALYST),
    Role.AUDITOR: _READ_ONLY | {AUDIT_VIEW, DASHBOARD_TEAM},
}


def role_of(user):
    if not user or not getattr(user, "is_authenticated", False):
        return None
    if user.is_superuser:
        return Role.ADMIN.value
    return getattr(user, "role", None) or Role.TIER1_ANALYST.value


def permissions_for(user):
    role = role_of(user)
    return sorted(ROLE_PERMISSIONS.get(role, set())) if role else []


def has_perm(user, permission):
    role = role_of(user)
    return bool(role) and permission in ROLE_PERMISSIONS.get(role, set())


def roles_catalog():
    return [
        {
            "value": role.value,
            "label": role.label,
            "description": ROLE_DESCRIPTIONS[role],
            "permissions": sorted(ROLE_PERMISSIONS[role]),
        }
        for role in Role
    ]
