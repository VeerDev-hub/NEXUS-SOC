from rest_framework import serializers

from apps.agentic.models import ActionProposal, AgentRun, AgentStep
from apps.agentic.multiagent.actions import ACTION_CATALOG


def _user_label(user):
    if not user:
        return None
    return {"id": user.pk, "username": user.username, "name": user.get_full_name() or user.username}


class AgentStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentStep
        fields = (
            "id", "sequence", "agent", "status", "routing_reason", "summary", "output", "tool_calls",
            "confidence", "llm_mode", "provider", "model", "fallback_reason", "tokens_in", "tokens_out",
            "latency_ms", "started_at", "completed_at", "error",
        )


class ActionProposalSerializer(serializers.ModelSerializer):
    action_label = serializers.SerializerMethodField()
    connector = serializers.SerializerMethodField()
    case_id = serializers.CharField(source="case.case_id", read_only=True)
    case_pk = serializers.UUIDField(source="case.pk", read_only=True)
    case_title = serializers.CharField(source="case.title", read_only=True)
    decided_by = serializers.SerializerMethodField()

    class Meta:
        model = ActionProposal
        fields = (
            "id", "case_pk", "case_id", "case_title", "run", "action_type", "action_label", "connector", "target",
            "rationale", "risk_level", "required_role", "status", "auto_approved", "decided_by", "decided_at",
            "decision_note", "executed_at", "execution_result", "created_at",
        )

    def get_action_label(self, obj):
        return ACTION_CATALOG.get(obj.action_type, {}).get("label", obj.action_type)

    def get_connector(self, obj):
        return ACTION_CATALOG.get(obj.action_type, {}).get("connector", "")

    def get_decided_by(self, obj):
        return _user_label(obj.decided_by)


class AgentRunListSerializer(serializers.ModelSerializer):
    case_id = serializers.CharField(source="case.case_id", read_only=True)
    case_pk = serializers.UUIDField(source="case.pk", read_only=True)
    case_title = serializers.CharField(source="case.title", read_only=True)
    triggered_by = serializers.SerializerMethodField()
    duration_ms = serializers.IntegerField(read_only=True)

    class Meta:
        model = AgentRun
        fields = (
            "id", "case_pk", "case_id", "case_title", "status", "trigger", "triggered_by", "llm_mode",
            "current_agent", "final_verdict", "final_severity", "final_confidence", "summary", "total_tokens",
            "started_at", "completed_at", "duration_ms", "error",
        )

    def get_triggered_by(self, obj):
        return _user_label(obj.triggered_by)


class AgentRunDetailSerializer(AgentRunListSerializer):
    steps = AgentStepSerializer(many=True, read_only=True)
    proposals = ActionProposalSerializer(many=True, read_only=True)

    class Meta(AgentRunListSerializer.Meta):
        fields = AgentRunListSerializer.Meta.fields + ("user_input", "report", "steps", "proposals")
