from apps.agentic.multiagent.orchestrator import run_agents_for_case
from apps.agentic.runtime.base import BasePlaybook


class Playbook(BasePlaybook):
    NAME = "Investigation"
    DESC = "Run the multi-agent SOC team (triage, threat intel, asset context, investigation, response, reporting) on the case."
    TAGS = ["System", "LLM", "Case", "Multi-Agent"]

    def run(self):
        if self.case is None:
            raise ValueError("Investigation playbook requires a linked case.")
        self.add_run_message(f"Dispatching the agent team for {self.case.case_id.upper()}.")
        run = run_agents_for_case(
            self.case,
            trigger="playbook",
            user=getattr(self.playbook_run, "user", None),
            user_input=self.user_input,
        )
        for step in run.steps.exclude(agent="supervisor").order_by("sequence"):
            self.add_run_message(f"{step.agent}: {step.summary[:300]}")
        return f"Agent run {run.pk} completed: {run.final_verdict} ({run.llm_mode})"
