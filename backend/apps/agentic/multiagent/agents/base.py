"""Base class for specialist agents.

An agent run has three phases:

1. ``gather``  - deterministic tool calls (threat intel, CMDB, SIEM, ...) that
                 collect evidence. Tool use is explicit and auditable.
2. ``reason``  - the LLM reads the case, prior agents' findings and the evidence
                 and returns the agent's typed output schema. When the LLM is not
                 available, ``offline`` produces the same schema with rules.
3. ``apply``   - side effects on the platform (enrichments, action proposals,
                 case AI fields).
"""

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from django.conf import settings

from apps.agentic.multiagent.guardrails import INJECTION_RULE

PROMPT_DIR = Path(settings.BASE_DIR) / "data" / "agents"

COMMON_RULES = f"""
General rules for every agent:
- Use only facts present in the input (case, artifacts, prior_findings, evidence). Never invent hosts, users, IPs or timestamps.
- When evidence is weak, say so and lower your confidence instead of guessing.
- Be concise and specific; another agent and a human analyst will read your output.
- Respond only through the required structured output.
{INJECTION_RULE}
"""


@lru_cache(maxsize=32)
def load_prompt(name):
    return (PROMPT_DIR / f"{name}.md").read_text(encoding="utf-8") + "\n" + COMMON_RULES


@dataclass
class AgentOutcome:
    output: object
    llm: object
    evidence: dict = field(default_factory=dict)


class BaseAgent:
    key = ""
    name = ""
    description = ""
    tools: tuple = ()
    output_schema = None

    # ---- hooks for subclasses ------------------------------------------------
    def gather(self, ctx, toolbox):
        return {}

    def offline(self, ctx, evidence):
        raise NotImplementedError

    def apply(self, ctx, output, *, run, step):
        return None

    def confidence(self, output):
        return getattr(output, "confidence_score", None)

    def summarize(self, output):
        return getattr(output, "summary", "") or ""

    # ---- driver -----------------------------------------------------------------
    def run(self, ctx, toolbox, gateway):
        evidence = self.gather(ctx, toolbox) or {}
        result = gateway.invoke(
            agent_key=self.key,
            system_prompt=load_prompt(self.key),
            payload=ctx.agent_payload(evidence),
            schema=self.output_schema,
            offline_fn=lambda: self.offline(ctx, evidence),
        )
        return AgentOutcome(output=result.output, llm=result, evidence=evidence)

    @classmethod
    def describe(cls):
        return {"key": cls.key, "name": cls.name, "description": cls.description, "tools": list(cls.tools)}
