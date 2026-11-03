from django.db import models
from django.utils import timezone

from apps.common.models import BaseModel


class AgenticJobStatus(models.TextChoices):
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCESS = "Success"
    FAILED = "Failed"


class CaseAnalysisJob(BaseModel):
    case = models.ForeignKey(
        "cases.Case",
        on_delete=models.CASCADE,
        related_name="agentic_analysis_jobs",
    )
    status = models.CharField(
        max_length=20,
        choices=AgenticJobStatus,
        default=AgenticJobStatus.PENDING,
        db_index=True,
    )
    trigger = models.CharField(max_length=100, blank=True, default="")
    scheduled_at = models.DateTimeField(default=timezone.now, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    queue_message_id = models.CharField(max_length=255, blank=True, default="")
    requested_by = models.ForeignKey(
        "accounts.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="case_analysis_jobs"
    )
    user_input = models.TextField(blank=True, default="")
    error = models.TextField(blank=True, default="")
    result_json = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "agentic_case_analysis_jobs"
        ordering = ["scheduled_at", "created_at"]

    def __str__(self):
        return f"{self.case.case_id or self.case_id} {self.status}"


class AgentRunStatus(models.TextChoices):
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"


class AgentStepStatus(models.TextChoices):
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    SKIPPED = "Skipped"


class LLMMode(models.TextChoices):
    ONLINE = "online"
    OFFLINE = "offline"
    MIXED = "mixed"


class AgentRun(BaseModel):
    """One multi-agent orchestration over a case."""

    case = models.ForeignKey("cases.Case", on_delete=models.CASCADE, related_name="agent_runs")
    job = models.ForeignKey(CaseAnalysisJob, null=True, blank=True, on_delete=models.SET_NULL, related_name="agent_runs")
    status = models.CharField(max_length=20, choices=AgentRunStatus, default=AgentRunStatus.RUNNING, db_index=True)
    trigger = models.CharField(max_length=100, blank=True, default="")
    triggered_by = models.ForeignKey(
        "accounts.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="agent_runs"
    )
    user_input = models.TextField(blank=True, default="")
    llm_mode = models.CharField(max_length=10, choices=LLMMode, blank=True, default="")
    current_agent = models.CharField(max_length=50, blank=True, default="")
    final_verdict = models.CharField(max_length=30, blank=True, default="")
    final_severity = models.CharField(max_length=20, blank=True, default="")
    final_confidence = models.PositiveSmallIntegerField(null=True, blank=True)
    summary = models.TextField(blank=True, default="")
    report = models.JSONField(default=dict, blank=True)
    total_tokens = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "agent_runs"
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["case", "-started_at"], name="agent_run_case_idx")]

    def __str__(self):
        return f"AgentRun {self.pk} ({self.status})"

    @property
    def duration_ms(self):
        if not self.completed_at:
            return None
        return int((self.completed_at - self.started_at).total_seconds() * 1000)


class AgentStep(BaseModel):
    """A single agent turn (including Supervisor routing decisions)."""

    run = models.ForeignKey(AgentRun, on_delete=models.CASCADE, related_name="steps")
    sequence = models.PositiveIntegerField()
    agent = models.CharField(max_length=50, db_index=True)
    status = models.CharField(max_length=20, choices=AgentStepStatus, default=AgentStepStatus.RUNNING)
    routing_reason = models.TextField(blank=True, default="")
    summary = models.TextField(blank=True, default="")
    output = models.JSONField(default=dict, blank=True)
    tool_calls = models.JSONField(default=list, blank=True)
    confidence = models.PositiveSmallIntegerField(null=True, blank=True)
    llm_mode = models.CharField(max_length=10, choices=LLMMode, blank=True, default="")
    provider = models.CharField(max_length=100, blank=True, default="")
    model = models.CharField(max_length=200, blank=True, default="")
    fallback_reason = models.TextField(blank=True, default="")
    tokens_in = models.PositiveIntegerField(default=0)
    tokens_out = models.PositiveIntegerField(default=0)
    latency_ms = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "agent_steps"
        ordering = ["run", "sequence"]
        constraints = [models.UniqueConstraint(fields=["run", "sequence"], name="agent_step_run_seq_uniq")]

    def __str__(self):
        return f"{self.agent} #{self.sequence}"


class ActionRiskLevel(models.TextChoices):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ActionProposalStatus(models.TextChoices):
    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    EXECUTED = "Executed"
    FAILED = "Failed"


class ActionProposal(BaseModel):
    """A response action proposed by the Response Agent; executed only after approval."""

    case = models.ForeignKey("cases.Case", on_delete=models.CASCADE, related_name="action_proposals")
    run = models.ForeignKey(AgentRun, null=True, blank=True, on_delete=models.SET_NULL, related_name="proposals")
    step = models.ForeignKey(AgentStep, null=True, blank=True, on_delete=models.SET_NULL, related_name="proposals")
    action_type = models.CharField(max_length=50)
    target = models.CharField(max_length=500)
    rationale = models.TextField(blank=True, default="")
    risk_level = models.CharField(max_length=20, choices=ActionRiskLevel, default=ActionRiskLevel.MEDIUM)
    required_role = models.CharField(max_length=30, blank=True, default="")
    status = models.CharField(
        max_length=20, choices=ActionProposalStatus, default=ActionProposalStatus.PENDING, db_index=True
    )
    auto_approved = models.BooleanField(default=False)
    decided_by = models.ForeignKey(
        "accounts.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="decided_proposals"
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.TextField(blank=True, default="")
    executed_at = models.DateTimeField(null=True, blank=True)
    execution_result = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "agent_action_proposals"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["case", "action_type", "target"], name="agent_action_case_target_uniq"),
        ]

    def __str__(self):
        return f"{self.action_type} -> {self.target} ({self.status})"
