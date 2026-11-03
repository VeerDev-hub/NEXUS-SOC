from django.db.models import Avg, Count, Q, Sum
from django.shortcuts import get_object_or_404
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts import rbac
from apps.accounts.permissions import ReadOrPermission
from apps.agentic.models import (
    ActionProposal,
    ActionProposalStatus,
    AgentRun,
    AgentRunStatus,
    AgentStep,
    AgentStepStatus,
    CaseAnalysisJob,
)
from apps.agentic.multiagent import events
from apps.agentic.multiagent.actions import can_approve, catalog, decide_proposal
from apps.agentic.multiagent.agents import AGENT_CLASSES
from apps.agentic.multiagent.llm_gateway import llm_status
from apps.agentic.multiagent.supervisor import Supervisor
from apps.agentic.serializers import ActionProposalSerializer, AgentRunDetailSerializer, AgentRunListSerializer
from apps.agentic.services.cases import request_case_analysis
from apps.cases.models import Case


class AgentCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "agents": [Supervisor.describe()] + [cls.describe() for cls in AGENT_CLASSES],
            "actions": catalog(),
            "llm": llm_status(),
        })


class LLMStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(llm_status(force_probe=request.query_params.get("probe") == "1"))


class AgentMetricsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        per_agent = (
            AgentStep.objects.values("agent")
            .annotate(
                runs=Count("id"),
                completed=Count("id", filter=Q(status=AgentStepStatus.COMPLETED)),
                failed=Count("id", filter=Q(status=AgentStepStatus.FAILED)),
                offline=Count("id", filter=Q(llm_mode="offline")),
                avg_latency_ms=Avg("latency_ms"),
                tokens=Sum("tokens_in") + Sum("tokens_out"),
                avg_confidence=Avg("confidence"),
            )
            .order_by("agent")
        )
        runs = AgentRun.objects.aggregate(
            total=Count("id"),
            completed=Count("id", filter=Q(status=AgentRunStatus.COMPLETED)),
            failed=Count("id", filter=Q(status=AgentRunStatus.FAILED)),
            running=Count("id", filter=Q(status=AgentRunStatus.RUNNING)),
            tokens=Sum("total_tokens"),
        )
        verdicts = list(
            AgentRun.objects.filter(status=AgentRunStatus.COMPLETED)
            .values("final_verdict").annotate(count=Count("id")).order_by("-count")
        )
        proposals = list(ActionProposal.objects.values("status").annotate(count=Count("id")))
        return Response({"agents": list(per_agent), "runs": runs, "verdicts": verdicts, "proposals": proposals})


class AgentRunViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    filterset_fields = ["case", "status", "llm_mode"]
    ordering_fields = ["started_at", "completed_at"]

    def get_queryset(self):
        qs = AgentRun.objects.select_related("case", "triggered_by")
        if self.action == "retrieve":
            qs = qs.prefetch_related("steps", "proposals__case", "proposals__decided_by")
        return qs

    def get_serializer_class(self):
        return AgentRunDetailSerializer if self.action == "retrieve" else AgentRunListSerializer


class CaseAgentRunView(APIView):
    """POST /cases/<pk>/agent-runs/ queues the agent team; GET lists runs for the case."""

    permission_classes = [ReadOrPermission.of(rbac.AGENTS_RUN)]

    def get(self, request, case_pk):
        case = get_object_or_404(Case, pk=case_pk)
        runs = AgentRun.objects.filter(case=case).select_related("case", "triggered_by")[:20]
        return Response(AgentRunListSerializer(runs, many=True).data)

    def post(self, request, case_pk):
        case = get_object_or_404(Case, pk=case_pk)
        job = request_case_analysis(
            case=case,
            trigger="manual",
            requested_by=request.user,
            user_input=str(request.data.get("user_input") or "")[:4000],
        )
        return Response({"job_id": str(job.pk), "status": job.status}, status=status.HTTP_202_ACCEPTED)


class ActionProposalViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = ActionProposalSerializer
    filterset_fields = ["case", "status", "risk_level", "required_role", "run"]
    ordering_fields = ["created_at", "risk_level"]

    def get_queryset(self):
        return ActionProposal.objects.select_related("case", "decided_by")

    @action(detail=True, methods=["post"])
    def decide(self, request, pk=None):
        proposal = self.get_object()
        if not rbac.has_perm(request.user, rbac.ACTIONS_APPROVE) or not can_approve(rbac.role_of(request.user), proposal):
            return Response(
                {"detail": f"Your role cannot decide this action (requires {proposal.required_role or 'an analyst'})."},
                status=status.HTTP_403_FORBIDDEN,
            )
        approve = bool(request.data.get("approve"))
        try:
            proposal = decide_proposal(proposal, user=request.user, approve=approve, note=str(request.data.get("note") or "")[:2000])
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        events.proposal_event("agent.proposal.updated", proposal)
        return Response(ActionProposalSerializer(proposal).data)

    @action(detail=False, methods=["get"])
    def summary(self, request):
        counts = dict(ActionProposal.objects.values_list("status").annotate(c=Count("id")))
        return Response({
            "pending": counts.get(ActionProposalStatus.PENDING, 0),
            "executed": counts.get(ActionProposalStatus.EXECUTED, 0),
            "rejected": counts.get(ActionProposalStatus.REJECTED, 0),
            "queued_jobs": CaseAnalysisJob.objects.filter(status="Pending").count(),
        })


class DemoScenarioView(APIView):
    """GET lists demo attack scenarios; POST {"key": ...} generates one (alerts -> case -> agents)."""

    permission_classes = [ReadOrPermission.of(rbac.AGENTS_RUN)]

    def get(self, request):
        from apps.agentic.demo import list_scenarios

        return Response(list_scenarios())

    def post(self, request):
        from apps.agentic.demo import launch

        try:
            case = launch(str(request.data.get("key", "")))
        except KeyError:
            return Response({"detail": "Unknown scenario."}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"case_pk": str(case.pk), "case_id": case.case_id, "title": case.title}, status=status.HTTP_201_CREATED)
