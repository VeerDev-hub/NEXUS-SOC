"""Realtime events for the agent timeline (delivered over the existing WebSocket)."""

import json
import logging

from django.core.serializers.json import DjangoJSONEncoder

from apps.realtime.events import _event, _send_group
from apps.realtime.groups import AGENTS_FEED_GROUP

logger = logging.getLogger(__name__)


def _emit(event_type, payload):
    """Publish to the live feed. Never lets a notification failure break an agent run."""
    try:
        # Serializer output can hold UUID/datetime objects the channel layer cannot encode.
        safe = json.loads(json.dumps(payload, cls=DjangoJSONEncoder))
        _send_group(AGENTS_FEED_GROUP, _event(event_type, safe))
    except Exception:
        logger.exception("Failed to publish realtime agent event %s", event_type)


def run_event(event_type, run):
    from apps.agentic.serializers import AgentRunListSerializer

    _emit(event_type, {"run": AgentRunListSerializer(run).data})


def step_event(event_type, step):
    from apps.agentic.serializers import AgentStepSerializer

    _emit(event_type, {"run_id": str(step.run_id), "case_pk": str(step.run.case_id), "step": AgentStepSerializer(step).data})


def proposal_event(event_type, proposal):
    from apps.agentic.serializers import ActionProposalSerializer

    _emit(event_type, {"proposal": ActionProposalSerializer(proposal).data})
