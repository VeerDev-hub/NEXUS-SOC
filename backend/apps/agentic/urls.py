from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    ActionProposalViewSet,
    AgentCatalogView,
    AgentMetricsView,
    AgentRunViewSet,
    CaseAgentRunView,
    DemoScenarioView,
    LLMStatusView,
)

router = DefaultRouter()
router.register("agent-runs", AgentRunViewSet, basename="agent-run")
router.register("action-proposals", ActionProposalViewSet, basename="action-proposal")

urlpatterns = [
    path("agents/", AgentCatalogView.as_view(), name="agent-catalog"),
    path("agents/llm-status/", LLMStatusView.as_view(), name="agent-llm-status"),
    path("agents/metrics/", AgentMetricsView.as_view(), name="agent-metrics"),
    path("demo/scenarios/", DemoScenarioView.as_view(), name="demo-scenarios"),
    path("cases/<uuid:case_pk>/agent-runs/", CaseAgentRunView.as_view(), name="case-agent-runs"),
    path("", include(router.urls)),
]
