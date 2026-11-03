"""Live SOC KPIs for the role dashboards (computed on request, no cache worker needed)."""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Avg, Count, DurationField, ExpressionWrapper, F, Q
from django.db.models import Value
from django.db.models.functions import Coalesce, NullIf, TruncDate, TruncHour
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.agentic.models import ActionProposal, ActionProposalStatus, AgentRun, AgentRunStatus
from apps.alerts.models import Alert
from apps.cases.models import Case, CaseStatus

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
OPEN_STATUSES = [CaseStatus.NEW, CaseStatus.IN_PROGRESS, CaseStatus.ON_HOLD]
CLOSED_STATUSES = [CaseStatus.RESOLVED, CaseStatus.CLOSED]


TREND_DAYS = 14
TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]


def _effective_severity(qs):
    """AI severity when the agents have assessed the case, otherwise the source severity."""
    return qs.annotate(eff_sev=Coalesce(NullIf("severity_ai", Value("")), "severity"))


def _cases_daily(cases, now):
    start = timezone.localdate(now) - timedelta(days=TREND_DAYS - 1)
    rows = (
        _effective_severity(cases.filter(created_at__date__gte=start))
        .annotate(day=TruncDate("created_at"))
        .values("day", "eff_sev")
        .annotate(count=Count("id"))
    )
    grid = {start + timedelta(days=i): {s: 0 for s in SEVERITIES[:4]} for i in range(TREND_DAYS)}
    for row in rows:
        sev = row["eff_sev"] if row["eff_sev"] in SEVERITIES[:4] else "Low"
        if row["day"] in grid:
            grid[row["day"]][sev] += row["count"]
    return [{"day": day.isoformat(), **counts, "total": sum(counts.values())} for day, counts in grid.items()]


def _resolution_daily(cases, now):
    start = timezone.localdate(now) - timedelta(days=TREND_DAYS - 1)
    rows = (
        cases.filter(closed_time__isnull=False, closed_time__date__gte=start)
        .annotate(day=TruncDate("closed_time"))
        .values("day")
        .annotate(avg=Avg(ExpressionWrapper(F("closed_time") - F("created_at"), output_field=DurationField())), closed=Count("id"))
    )
    by_day = {r["day"]: r for r in rows}
    out = []
    for i in range(TREND_DAYS):
        day = start + timedelta(days=i)
        r = by_day.get(day)
        out.append({"day": day.isoformat(), "closed": r["closed"] if r else 0, "mttr_hours": round(r["avg"].total_seconds() / 3600, 1) if r and r["avg"] else None})
    return out


def _tactic_heatmap(alerts):
    rows = alerts.exclude(tactic="").values("tactic", "severity").annotate(count=Count("id"))
    cells = {}
    for r in rows:
        cells.setdefault(r["tactic"], {s: 0 for s in SEVERITIES[:4]})
        if r["severity"] in SEVERITIES[:4]:
            cells[r["tactic"]][r["severity"]] += r["count"]
    ordered = [t for t in TACTICS if t in cells] + sorted(t for t in cells if t not in TACTICS)
    return [{"tactic": t, **cells[t]} for t in ordered]


def _seconds(duration):
    return int(duration.total_seconds()) if duration else None


class SocMetricsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        now = timezone.now()
        since_24h = now - timedelta(hours=24)
        cases = Case.objects.all()
        open_cases = cases.filter(status__in=OPEN_STATUSES)

        by_severity = dict(open_cases.values_list("severity").annotate(c=Count("id")))
        by_status = dict(cases.values_list("status").annotate(c=Count("id")))
        by_tier = dict(open_cases.values_list("tier").annotate(c=Count("id")))

        closed = cases.filter(status__in=CLOSED_STATUSES, closed_time__isnull=False)
        mttr = closed.aggregate(v=Avg(ExpressionWrapper(F("closed_time") - F("created_at"), output_field=DurationField())))["v"]
        runs_done = AgentRun.objects.filter(status=AgentRunStatus.COMPLETED, completed_at__isnull=False)
        mtt_ai = runs_done.aggregate(v=Avg(ExpressionWrapper(F("completed_at") - F("started_at"), output_field=DurationField())))["v"]
        mtta = cases.filter(acknowledged_time__isnull=False).aggregate(
            v=Avg(ExpressionWrapper(F("acknowledged_time") - F("created_at"), output_field=DurationField()))
        )["v"]

        reviewed = cases.exclude(verdict="").exclude(verdict_ai="")
        agree = reviewed.filter(verdict=F("verdict_ai")).count()

        hourly = {
            row["hour"].isoformat(): row["count"]
            for row in Alert.objects.filter(created_at__gte=since_24h)
            .annotate(hour=TruncHour("created_at")).values("hour").annotate(count=Count("id"))
        }
        trend = []
        start = (now - timedelta(hours=23)).replace(minute=0, second=0, microsecond=0)
        for i in range(24):
            hour = start + timedelta(hours=i)
            key = timezone.localtime(hour).replace(minute=0, second=0, microsecond=0).isoformat()
            trend.append({"hour": hour.isoformat(), "alerts": hourly.get(key, 0) + hourly.get(hour.isoformat(), 0)})

        User = get_user_model()
        workload = [
            {"user": u.get_full_name() or u.username, "username": u.username, "role": u.role, "open_cases": u.open_cases}
            for u in User.objects.filter(is_active=True, role__in=["tier1_analyst", "tier2_responder", "soc_manager"])
            .annotate(open_cases=Count("assigned_cases", filter=Q(assigned_cases__status__in=OPEN_STATUSES)))
            .order_by("-open_cases", "username")
        ]

        status_order = ["New", "In Progress", "On Hold", "Resolved", "Closed"]
        pipeline = [{"status": s, "count": by_status.get(s, 0)} for s in status_order]
        sources = [
            {"source": r["product_category"] or "Other", "count": r["count"]}
            for r in Alert.objects.values("product_category").annotate(count=Count("id")).order_by("-count")[:8]
        ]
        open_sev = dict(_effective_severity(open_cases).values_list("eff_sev").annotate(c=Count("id")))
        verdict_pairs = list(
            reviewed.values("verdict_ai", "verdict").annotate(count=Count("id")).order_by("-count")[:10]
        )

        techniques = list(
            Alert.objects.exclude(technique="").values("technique").annotate(count=Count("id")).order_by("-count")[:8]
        )
        proposals = dict(ActionProposal.objects.values_list("status").annotate(c=Count("id")))

        return Response({
            "generated_at": now.isoformat(),
            "cases": {
                "total": cases.count(),
                "open": open_cases.count(),
                "critical_open": open_cases.filter(severity="Critical").count(),
                "unassigned_open": open_cases.filter(assignee__isnull=True).count(),
                "by_severity": [{"severity": s, "count": by_severity.get(s, 0)} for s in SEVERITIES],
                "by_status": by_status,
                "by_tier": {"L1": by_tier.get("L1", 0), "L2": by_tier.get("L2", 0)},
                "auto_escalated": cases.filter(escalated_at__isnull=False, escalated_by__isnull=True).count(),
                "closed_24h": cases.filter(closed_time__gte=since_24h).count(),
            },
            "alerts": {"last_24h": Alert.objects.filter(created_at__gte=since_24h).count(), "trend": trend},
            "timings": {
                "mttr_seconds": _seconds(mttr),
                "mtta_seconds": _seconds(mtta),
                "ai_triage_seconds": round(mtt_ai.total_seconds(), 1) if mtt_ai else None,
            },
            "ai": {
                "runs_total": AgentRun.objects.count(),
                "runs_24h": AgentRun.objects.filter(started_at__gte=since_24h).count(),
                "reviewed_cases": reviewed.count(),
                "agreement_rate": round(100 * agree / reviewed.count(), 1) if reviewed.exists() else None,
                "verdicts": list(runs_done.values("final_verdict").annotate(count=Count("id")).order_by("-count")),
            },
            "actions": {
                "pending": proposals.get(ActionProposalStatus.PENDING, 0),
                "executed": proposals.get(ActionProposalStatus.EXECUTED, 0),
                "rejected": proposals.get(ActionProposalStatus.REJECTED, 0),
                "auto_approved": ActionProposal.objects.filter(auto_approved=True).count(),
            },
            "workload": workload,
            "charts": {
                "cases_daily": _cases_daily(cases, now),
                "resolution_daily": _resolution_daily(cases, now),
                "open_by_severity": [{"severity": s, "count": open_sev.get(s, 0)} for s in SEVERITIES[:4]],
                "pipeline": pipeline,
                "alert_sources": sources,
                "tactic_heatmap": _tactic_heatmap(Alert.objects.all()),
                "verdict_pairs": verdict_pairs,
            },
            "top_techniques": techniques,
        })
