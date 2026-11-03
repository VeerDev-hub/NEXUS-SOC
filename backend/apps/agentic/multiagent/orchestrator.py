"""Runs the Supervisor + specialist agents over a case and persists every step."""

import logging
import time

from django.conf import settings

from django.utils import timezone

from apps.agentic.models import AgentRun, AgentRunStatus, AgentStep, AgentStepStatus, LLMMode
from apps.agentic.multiagent import events
from apps.agentic.multiagent.agents import get_agent
from apps.agentic.multiagent.context import CaseContext
from apps.agentic.multiagent.llm_gateway import LLMGateway
from apps.agentic.multiagent.schemas import FINISH
from apps.agentic.multiagent.supervisor import Supervisor
from apps.agentic.multiagent.tools import Toolbox
from apps.cases.escalation import maybe_auto_escalate
from apps.notifications.service import notify_case_verdict
from apps.settings.runtime_config import get_runtime_config

logger = logging.getLogger(__name__)

DEFAULT_MAX_STEPS = 10


def _max_steps():
    try:
        return max(4, int(get_runtime_config().get("agent_max_steps") or DEFAULT_MAX_STEPS))
    except Exception:
        return DEFAULT_MAX_STEPS


def _offline_pace_ms():
    return max(0, int(getattr(settings, "AGENT_OFFLINE_STEP_DELAY_MS", 0) or 0))


class Orchestrator:
    def __init__(self, *, gateway=None, max_steps=None, pace_ms=0):
        self.gateway = gateway or LLMGateway()
        self.max_steps = max_steps or _max_steps()
        # Offline steps finish in milliseconds; a small pause makes the live timeline watchable in demos.
        self.pace_ms = pace_ms
        self.supervisor = Supervisor()
        self._modes = set()

    # ---- persistence helpers ----------------------------------------------------
    def _new_step(self, run, agent_key, routing_reason=""):
        sequence = run.steps.count() + 1
        step = AgentStep.objects.create(run=run, sequence=sequence, agent=agent_key, routing_reason=routing_reason)
        run.current_agent = agent_key
        run.save(update_fields=["current_agent", "updated_at"])
        events.step_event("agent.step.started", step)
        return step

    def _finish_step(self, step, *, llm=None, **fields):
        if self.pace_ms and (llm is None or llm.mode == "offline"):
            time.sleep(self.pace_ms / 1000)
        if llm is not None:
            self._modes.add(llm.mode)
            fields.update(
                llm_mode=llm.mode,
                provider=llm.provider,
                model=llm.model,
                fallback_reason=llm.fallback_reason,
                tokens_in=llm.tokens_in,
                tokens_out=llm.tokens_out,
                latency_ms=llm.latency_ms,
            )
        for key, value in fields.items():
            setattr(step, key, value)
        step.completed_at = timezone.now()
        if not fields.get("latency_ms"):
            step.latency_ms = int((step.completed_at - step.started_at).total_seconds() * 1000)
        step.save()
        events.step_event("agent.step.completed", step)
        return step

    # ---- main loop -------------------------------------------------------------------
    def run(self, case, *, trigger="manual", user=None, user_input="", job=None):
        run = AgentRun.objects.create(
            case=case,
            job=job,
            trigger=trigger,
            triggered_by=user if getattr(user, "is_authenticated", False) else None,
            user_input=user_input or "",
        )
        events.run_event("agent.run.started", run)
        try:
            ctx = CaseContext.build(case, user_input=user_input)
            toolbox = Toolbox(case)
            steps_taken = 0
            while steps_taken < self.max_steps:
                steps_left = self.max_steps - steps_taken
                routing_step = self._new_step(run, self.supervisor.key)
                routing, llm = self.supervisor.decide(ctx, self.gateway, steps_left=steps_left)
                self._finish_step(
                    routing_step,
                    llm=llm,
                    status=AgentStepStatus.COMPLETED,
                    summary=f"Next: {routing.next_agent}",
                    routing_reason=routing.reasoning,
                    output={"next_agent": routing.next_agent, "overridden": routing.overridden},
                )
                if routing.next_agent == FINISH:
                    break
                self._run_agent(run, ctx, toolbox, routing)
                steps_taken += 1
            self._complete(run, ctx)
        except Exception as exc:
            logger.exception("Agent run failed for case %s", case.pk)
            run.status = AgentRunStatus.FAILED
            run.error = f"{type(exc).__name__}: {exc}"
            run.completed_at = timezone.now()
            run.current_agent = ""
            run.save()
            events.run_event("agent.run.completed", run)
            raise
        return run

    def _run_agent(self, run, ctx, toolbox, routing):
        agent = get_agent(routing.next_agent)
        step = self._new_step(run, agent.key, routing.reasoning)
        toolbox.reset()
        try:
            outcome = agent.run(ctx, toolbox, self.gateway)
            output = outcome.output
            ctx.findings[agent.key] = output.model_dump(mode="json")
            side_effects = agent.apply(ctx, output, run=run, step=step)
            if side_effects:
                for proposal in side_effects:
                    events.proposal_event("agent.proposal.created", proposal)
            self._finish_step(
                step,
                llm=outcome.llm,
                status=AgentStepStatus.COMPLETED,
                summary=agent.summarize(output),
                output=ctx.findings[agent.key],
                tool_calls=toolbox.reset(),
                confidence=agent.confidence(output),
            )
        except Exception as exc:
            logger.exception("Agent %s failed", agent.key)
            self._finish_step(step, status=AgentStepStatus.FAILED, error=f"{type(exc).__name__}: {exc}", tool_calls=toolbox.reset())
            # Mark as done so the Supervisor does not loop on a broken agent.
            ctx.findings.setdefault(agent.key, {"summary": f"{agent.name} failed: {exc}"})

    def _complete(self, run, ctx):
        report = ctx.findings.get("reporting") or {}
        triage = ctx.findings.get("triage") or {}
        investigation = ctx.findings.get("investigation") or {}
        run.status = AgentRunStatus.COMPLETED
        run.report = report
        run.final_verdict = report.get("verdict") or investigation.get("verdict") or triage.get("verdict", "")
        run.final_severity = report.get("severity") or triage.get("severity", "")
        run.final_confidence = investigation.get("confidence_score") or triage.get("confidence_score")
        run.summary = report.get("executive_summary") or triage.get("summary", "")
        run.llm_mode = (
            LLMMode.MIXED if len(self._modes) > 1 else (next(iter(self._modes)) if self._modes else LLMMode.OFFLINE)
        )
        run.total_tokens = sum(s.tokens_in + s.tokens_out for s in run.steps.all())
        run.current_agent = ""
        run.completed_at = timezone.now()
        run.save()
        maybe_auto_escalate(run.case, verdict=run.final_verdict, severity=run.final_severity, summary=run.summary)
        try:
            notify_case_verdict(run)
        except Exception:
            logger.exception("Alert notification failed for case %s", run.case_id)
        events.run_event("agent.run.completed", run)


def run_agents_for_case(case, **kwargs):
    return Orchestrator(pace_ms=_offline_pace_ms()).run(case, **kwargs)
