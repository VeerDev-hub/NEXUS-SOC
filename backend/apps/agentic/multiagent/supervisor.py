"""Supervisor: decides which specialist agent runs next.

Routing is LLM-driven but bounded by guardrails:

* ``allowed_next`` computes the legal moves from the current state
  (e.g. triage must run first, response needs an investigation, reporting ends).
* The LLM picks one of the legal moves and explains why.
* If the LLM is offline, picks an illegal move, or fails, the deterministic
  ``policy_next`` is used and the override is recorded for the audit trail.
"""

from dataclasses import dataclass

from apps.agentic.multiagent.agents import AGENTS
from apps.agentic.multiagent.agents.base import load_prompt
from apps.agentic.multiagent.schemas import FINISH, SupervisorDecision

BENIGN_VERDICTS = ("False Positive", "Benign")
FAST_CLOSE_CONFIDENCE = 80


@dataclass
class Routing:
    next_agent: str
    reasoning: str
    overridden: bool = False


def _done(ctx):
    return set(ctx.findings)


def _triage(ctx):
    return ctx.findings.get("triage") or {}


def _is_benign_fast_path(ctx):
    triage = _triage(ctx)
    return triage.get("verdict") in BENIGN_VERDICTS and int(triage.get("confidence_score", 0)) >= FAST_CLOSE_CONFIDENCE


def _current_verdict(ctx):
    return (ctx.findings.get("investigation") or {}).get("verdict") or _triage(ctx).get("verdict")


def allowed_next(ctx, *, steps_left):
    done = _done(ctx)
    if "triage" not in done:
        return ["triage"]
    if "reporting" in done:
        return [FINISH]
    if steps_left <= 1:
        return ["reporting"]
    options = []
    if "threat_intel" not in done and ctx.ioc_artifacts():
        options.append("threat_intel")
    if "asset_context" not in done and (ctx.host_artifacts() or ctx.identity_artifacts() or ctx.cloud_artifacts()):
        options.append("asset_context")
    if "investigation" not in done:
        options.append("investigation")
    if "response" not in done and "investigation" in done and _current_verdict(ctx) not in BENIGN_VERDICTS:
        options.append("response")
    options.append("reporting")
    return options


def policy_next(ctx, *, steps_left):
    options = allowed_next(ctx, steps_left=steps_left)
    if options in (["triage"], [FINISH], ["reporting"]):
        reason = {
            "triage": "Every case starts with triage.",
            FINISH: "Final report is written; the investigation is complete.",
            "reporting": (
                "Step budget nearly exhausted; consolidate findings into the report."
                if steps_left <= 1 else
                "All relevant specialists have reported; consolidate their findings into the final report."
            ),
        }[options[0]]
        return Routing(options[0], reason)
    if _is_benign_fast_path(ctx) and "investigation" not in _done(ctx):
        return Routing("reporting", f"Triage is confident ({_triage(ctx).get('confidence_score')}%) this is {_triage(ctx).get('verdict')}; skip deep investigation and close out with a report.")
    for key, reason in (
        ("threat_intel", "External indicators present; check their reputation before deeper analysis."),
        ("asset_context", "Hosts/users involved; establish business criticality and blast radius."),
        ("investigation", "Enough context gathered; reconstruct the timeline and map to ATT&CK."),
        ("response", f"Verdict is {_current_verdict(ctx)}; plan containment."),
        ("reporting", "All necessary analysis is complete; produce the final report."),
    ):
        if key in options:
            return Routing(key, reason)
    return Routing("reporting", "Fallback to reporting.")


def _state_summary(ctx, options):
    agents = {key: AGENTS[key].description for key in options if key in AGENTS}
    return {
        "case_title": ctx.payload.get("title"),
        "artifact_counts": {
            "external_iocs": len(ctx.ioc_artifacts()),
            "hosts": len(ctx.host_artifacts()),
            "identities": len(ctx.identity_artifacts()),
            "cloud_resources": len(ctx.cloud_artifacts()),
        },
        "completed_agents": {k: (v.get("summary") or v.get("attack_narrative") or v.get("executive_summary") or "") for k, v in ctx.findings.items()},
        "allowed_next": options,
        "agent_descriptions": agents,
    }


class Supervisor:
    key = "supervisor"
    name = "Supervisor"
    description = "Plans the investigation: reads the shared case state and routes work to the right specialist agent."

    def decide(self, ctx, gateway, *, steps_left):
        options = allowed_next(ctx, steps_left=steps_left)
        fallback = policy_next(ctx, steps_left=steps_left)
        if len(options) == 1:
            # Only one legal move: no need to spend an LLM call.
            return Routing(options[0], fallback.reasoning), None

        result = gateway.invoke(
            agent_key=self.key,
            system_prompt=load_prompt(self.key),
            payload=_state_summary(ctx, options),
            schema=SupervisorDecision,
            offline_fn=lambda: SupervisorDecision(next_agent=fallback.next_agent, reasoning=fallback.reasoning),
        )
        decision = result.output
        if decision.next_agent not in options:
            return Routing(fallback.next_agent, f"Guardrail override: '{decision.next_agent}' is not allowed now. {fallback.reasoning}", overridden=True), result
        return Routing(decision.next_agent, decision.reasoning), result

    @classmethod
    def describe(cls):
        return {"key": cls.key, "name": cls.name, "description": cls.description, "tools": []}
