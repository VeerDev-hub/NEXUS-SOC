"""Seed a realistic two-week SOC history for demos.

Every case goes through the real pipeline: detection module -> case/alerts/artifacts ->
the multi-agent team (offline engine, so no API key or internet needed). The command then
shifts each case back in time and simulates the human side: acknowledgement, assignment,
approvals and resolution, so dashboards show genuine trends, MTTR and AI/analyst agreement.

    python manage.py seed_demo            # add history
    python manage.py seed_demo --reset    # wipe cases/alerts/agent data first
"""

import random
from datetime import timedelta

from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db.models import F
from django.utils import timezone

from apps.accounts.models import User
from apps.agentic import demo
from apps.agentic.models import ActionProposal, ActionProposalStatus, AgentRun, AgentStep, CaseAnalysisJob
from apps.agentic.multiagent import events
from apps.agentic.multiagent.actions import execute_proposal
from apps.agentic.multiagent.llm_gateway import MODE_OFFLINE, LLMGateway
from apps.agentic.multiagent.orchestrator import Orchestrator
from apps.alerts.models import Alert
from apps.artifacts.models import Artifact
from apps.cases.models import Case, CaseStatus
from apps.enrichments.models import Enrichment
from apps.knowledge.models import Knowledge, KnowledgeSource

WEIGHTS = {"phishing": 26, "vpn_bruteforce": 18, "authorized_scan": 18, "encoded_powershell": 14, "ransomware": 12, "cloud_privesc": 12}
# Hours from creation to resolution, by severity (min, max).
RESOLVE_HOURS = {"Critical": (1, 6), "High": (2, 14), "Medium": (4, 30), "Low": (0.3, 4)}
ANALYST_OVERRIDES = {"True Positive": "Suspicious", "False Positive": "Benign", "Suspicious": "True Positive"}

KNOWLEDGE = [
    {
        "title": "Authorized vulnerability scanner scan-nessus-01",
        "body": "Host scan-nessus-01 (10.0.5.20) runs the authorized weekly Nessus scan and the quarterly pentest. "
        "Port scans and service discovery from this host during the scan window are expected and known benign.",
        "tags": ["whitelist", "scanner", "pentest", "authorized"],
    },
    {
        "title": "SOP: Ransomware precursor (shadow copy deletion)",
        "body": "1. Isolate the host from the network. 2. Disable the executing account. 3. Preserve memory and disk. "
        "4. Check backups for integrity. 5. Hunt for the same hash and C2 across the estate.",
        "tags": ["ransomware", "sop", "vssadmin"],
    },
    {
        "title": "VPN access policy",
        "body": "Service accounts (svc_*) must never log in over VPN. Any VPN session for a service account is a policy violation.",
        "tags": ["vpn", "policy", "svc_backup"],
    },
]


class Command(BaseCommand):
    help = "Seed two weeks of realistic SOC history (cases processed by the agent team)."

    def add_arguments(self, parser):
        parser.add_argument("--cases", type=int, default=48)
        parser.add_argument("--days", type=int, default=14)
        parser.add_argument("--reset", action="store_true", help="Delete existing cases, alerts, artifacts and agent data first.")
        parser.add_argument("--seed", type=int, default=2026)
        parser.add_argument("--if-empty", action="store_true", help="Only seed when there are no cases yet (safe on every container start).")

    def handle(self, *args, **opts):
        if opts["if_empty"] and Case.objects.exists():
            call_command("seed_demo_users", stdout=self.stdout)
            self.stdout.write("Cases already exist; skipping demo history.")
            return
        random.seed(opts["seed"])
        original_emit = events._emit
        events._emit = lambda *a, **k: None  # no live-event flood while seeding
        try:
            if opts["reset"]:
                self._reset()
            call_command("seed_demo_users", stdout=self.stdout)
            self._knowledge()
            self._history(opts["cases"], opts["days"])
        finally:
            events._emit = original_emit
        self.stdout.write(self.style.SUCCESS("Demo data ready."))

    # ------------------------------------------------------------------
    def _reset(self):
        for model in (ActionProposal, AgentStep, AgentRun, CaseAnalysisJob, Enrichment, Alert, Case, Artifact):
            model.objects.all().delete()
        Knowledge.objects.filter(source=KnowledgeSource.MANUAL).delete()
        self.stdout.write("Cleared cases, alerts, artifacts and agent data.")

    def _knowledge(self):
        for item in KNOWLEDGE:
            Knowledge.objects.update_or_create(title=item["title"], defaults={"body": item["body"], "tags": item["tags"], "source": KnowledgeSource.MANUAL})

    def _history(self, count, days):
        users = {u.username: u for u in User.objects.filter(username__in=["analyst", "responder", "manager"])}
        orchestrator = Orchestrator(gateway=LLMGateway(mode=MODE_OFFLINE), pace_ms=0)
        keys = list(WEIGHTS)
        now = timezone.now()
        fresh = ["ransomware", "encoded_powershell", "phishing", "cloud_privesc", "encoded_powershell", "vpn_bruteforce", "authorized_scan"]
        for i in range(count):
            key = random.choices(keys, weights=[WEIGHTS[k] for k in keys])[0]
            if i >= count - len(fresh):
                key = fresh[i - (count - len(fresh))]  # a varied set of open cases for the live demo
            case = demo.launch(key)
            CaseAnalysisJob.objects.filter(case=case).delete()
            # Unique correlation id so later scenarios never merge into this backdated case.
            uid = f"{case.correlation_uid}-s{i}"
            Case.objects.filter(pk=case.pk).update(correlation_uid=uid)
            Alert.objects.filter(case=case).update(correlation_uid=uid)
            run = orchestrator.run(Case.objects.get(pk=case.pk), trigger="alert_created")

            # Spread over the window; slightly busier recently, and never in the future.
            age = timedelta(days=random.triangular(0, days, days * 0.35), hours=random.uniform(0, 6))
            if i >= count - len(fresh):
                age = timedelta(minutes=random.uniform(20, 300))  # a few fresh, still-open cases
            self._shift(case, run, age)
            self._humans(Case.objects.get(pk=case.pk), now, users, keep_open=i >= count - len(fresh))
            self.stdout.write(f"  {i + 1:>2}/{count} {key:<16} {run.final_verdict:<15} {age.days}d ago")

    @staticmethod
    def _shift(case, run, delta):
        Case.objects.filter(pk=case.pk).update(created_at=F("created_at") - delta, updated_at=F("updated_at") - delta)
        Case.objects.filter(pk=case.pk, escalated_at__isnull=False).update(escalated_at=F("escalated_at") - delta)
        Alert.objects.filter(case=case).update(
            created_at=F("created_at") - delta,
            first_seen_time=F("first_seen_time") - delta,
            last_seen_time=F("last_seen_time") - delta,
        )
        Enrichment.objects.filter(case=case).update(created_at=F("created_at") - delta, updated_at=F("updated_at") - delta)
        AgentRun.objects.filter(pk=run.pk).update(started_at=F("started_at") - delta, completed_at=F("completed_at") - delta, created_at=F("created_at") - delta)
        AgentStep.objects.filter(run=run).update(started_at=F("started_at") - delta, completed_at=F("completed_at") - delta)
        ActionProposal.objects.filter(case=case).update(created_at=F("created_at") - delta)
        ActionProposal.objects.filter(case=case, decided_at__isnull=False).update(decided_at=F("decided_at") - delta, executed_at=F("executed_at") - delta)

    def _humans(self, case, now, users, keep_open=False):
        sev = case.severity_ai or case.severity or "Medium"
        lo, hi = RESOLVE_HOURS.get(sev, (2, 20))
        resolve_after = timedelta(hours=random.uniform(lo, hi))
        owner = users["responder"] if case.tier == "L2" else users["analyst"]
        acknowledged = case.created_at + timedelta(minutes=random.uniform(3, 35))
        if keep_open or case.created_at + resolve_after > now - timedelta(minutes=30) or random.random() < 0.12:
            # Still being worked on: most open cases already have an owner.
            if random.random() < 0.7 and acknowledged < now:
                Case.objects.filter(pk=case.pk).update(assignee=owner, acknowledged_time=acknowledged, status=CaseStatus.IN_PROGRESS)
            return
        closed = case.created_at + resolve_after
        verdict = case.verdict_ai or "Suspicious"
        if random.random() < 0.12:
            verdict = ANALYST_OVERRIDES.get(verdict, verdict)

        for p in ActionProposal.objects.filter(case=case, status=ActionProposalStatus.PENDING):
            approver = users["manager"] if p.required_role == "soc_manager" else random.choice([users["responder"], users["manager"]])
            approve = random.random() < 0.85
            p.status = ActionProposalStatus.APPROVED if approve else ActionProposalStatus.REJECTED
            p.decided_by = approver
            p.decided_at = acknowledged + timedelta(minutes=random.uniform(2, 40))
            p.decision_note = "Confirmed with asset owner." if approve else "Not needed after host was rebuilt."
            p.save()
            if approve:
                p = execute_proposal(p)
                ActionProposal.objects.filter(pk=p.pk).update(executed_at=p.decided_at + timedelta(seconds=3))

        Case.objects.filter(pk=case.pk).update(
            assignee=owner,
            acknowledged_time=acknowledged,
            status=random.choice([CaseStatus.RESOLVED, CaseStatus.CLOSED, CaseStatus.CLOSED]),
            verdict=verdict,
            summary="Investigated with the AI team's report; containment completed and owner informed."
            if verdict in ("True Positive", "Suspicious")
            else "Confirmed benign/expected activity; no action required.",
            closed_time=closed,
            updated_at=closed,
        )
