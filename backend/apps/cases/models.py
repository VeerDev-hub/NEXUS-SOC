from django.conf import settings
from django.core.validators import MaxLengthValidator
from django.db import models

from apps.common.models import BaseModel
from apps.common.readable_ids import save_with_readable_id


class CaseSeverity(models.TextChoices):
    UNKNOWN = "Unknown"
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class CaseImpact(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class CasePriority(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class CaseConfidence(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class CaseStatus(models.TextChoices):
    NEW = "New"
    IN_PROGRESS = "In Progress"
    ON_HOLD = "On Hold"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


class CaseVerdict(models.TextChoices):
    UNKNOWN = "Unknown"
    FALSE_POSITIVE = "False Positive"
    TRUE_POSITIVE = "True Positive"
    DISREGARD = "Disregard"
    SUSPICIOUS = "Suspicious"
    BENIGN = "Benign"
    TEST = "Test"
    INSUFFICIENT_DATA = "Insufficient Data"
    SECURITY_RISK = "Security Risk"
    MANAGED_EXTERNALLY = "Managed Externally"
    DUPLICATE = "Duplicate"
    OTHER = "Other"


class CaseTier(models.TextChoices):
    L1 = "L1", "Tier-1 queue"
    L2 = "L2", "Tier-2 queue"


class CaseRelationshipType(models.TextChoices):
    RELATED = "Related"
    DUPLICATE_OF = "Duplicate of", "Duplicate of"
    PARENT_OF = "Parent of", "Parent of"


class CaseCategory(models.TextChoices):
    DLP = "DLP", "DLP"
    EMAIL = "Email"
    OT = "OT", "OT"
    PROXY = "Proxy"
    UEBA = "UEBA", "UEBA"
    TI = "ThreatIntelligence", "TI"
    IAM = "IAM", "IAM"
    EDR = "EDR", "EDR"
    NDR = "NDR", "NDR"
    CLOUD = "Cloud"
    SIEM = "SIEM", "SIEM"
    WAF = "WAF", "WAF"
    OTHER = "Other"


class Case(BaseModel):
    case_id = models.CharField(max_length=32, unique=True, editable=False, db_index=True, blank=True, default="", help_text="Record ID e.g. case_000001")
    title = models.CharField(max_length=500, help_text="Case title")
    severity = models.CharField(max_length=20, choices=CaseSeverity, blank=True, default="", help_text="Analyst-assessed severity")
    impact = models.CharField(max_length=20, choices=CaseImpact, blank=True, default="", help_text="Analyst-assessed impact")
    priority = models.CharField(max_length=20, choices=CasePriority, blank=True, default="", help_text="Response priority")
    confidence = models.CharField(max_length=20, choices=CaseConfidence, blank=True, default="", help_text="Analyst-assessed confidence")
    description = models.TextField(blank=True, default="", help_text="Case description")
    category = models.CharField(max_length=30, choices=CaseCategory, blank=True, default="", help_text="Case category")
    tags = models.JSONField(default=list, blank=True, help_text="Case tags")
    status = models.CharField(max_length=20, choices=CaseStatus, default=CaseStatus.NEW, help_text="Case handling status")
    verdict = models.CharField(max_length=30, choices=CaseVerdict, blank=True, default="", help_text="Final verdict")
    summary = models.TextField(blank=True, default="", help_text="Closure summary")
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_cases",
        help_text="Current assigned analyst handling the case",
    )
    acknowledged_time = models.DateTimeField(null=True, blank=True, help_text="L1 first acknowledged time")
    closed_time = models.DateTimeField(null=True, blank=True, help_text="case close time")
    correlation_uid = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Case correlation ID")

    # Escalation workflow (Tier-1 -> Tier-2)
    tier = models.CharField(max_length=5, choices=CaseTier, default=CaseTier.L1, db_index=True, help_text="Which analyst queue owns the case")
    escalated_at = models.DateTimeField(null=True, blank=True)
    escalated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="escalated_cases",
        help_text="Analyst who escalated; empty when escalated automatically by the AI team",
    )
    escalation_reason = models.TextField(blank=True, default="")

    # AI fields
    severity_ai = models.CharField(max_length=20, choices=CaseSeverity, blank=True, default="", help_text="AI-assessed severity")
    confidence_ai = models.CharField(max_length=20, choices=CaseConfidence, blank=True, default="", help_text="AI-assessed confidence")
    impact_ai = models.CharField(max_length=20, choices=CaseImpact, blank=True, default="", help_text="AI-assessed impact")
    priority_ai = models.CharField(max_length=20, choices=CasePriority, blank=True, default="", help_text="AI-assessed response priority")
    verdict_ai = models.CharField(max_length=30, choices=CaseVerdict, blank=True, default="", help_text="AI-generated final verdict")
    investigation_report_ai_json = models.TextField(blank=True, default="", help_text="AI-generated investigation report JSON Format")

    def save(self, *args, **kwargs):
        return save_with_readable_id(self, "case_id", "case", *args, **kwargs)

    class Meta:
        db_table = "cases"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "-id"], name="case_created_id_idx"),
            models.Index(fields=["status", "severity"], name="case_status_severity_idx"),
            models.Index(fields=["updated_at"], name="case_updated_at_idx"),
            models.Index(fields=["acknowledged_time"], name="case_ack_time_idx"),
            models.Index(fields=["closed_time"], name="case_closed_time_idx"),
        ]

    def __str__(self):
        return self.title or str(self.id)


class CaseRelationship(BaseModel):
    source_case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="outgoing_relationships",
    )
    target_case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="incoming_relationships",
    )
    relationship_type = models.CharField(max_length=20, choices=CaseRelationshipType)
    note = models.TextField(blank=True, default="", validators=[MaxLengthValidator(500)])
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_case_relationships",
    )
    pair_key = models.CharField(max_length=73, unique=True, editable=False)

    @staticmethod
    def build_pair_key(source_case_id, target_case_id):
        first, second = sorted((str(source_case_id), str(target_case_id)))
        return f"{first}:{second}"

    def save(self, *args, **kwargs):
        self.pair_key = self.build_pair_key(self.source_case_id, self.target_case_id)
        return super().save(*args, **kwargs)

    class Meta:
        db_table = "case_relationships"
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(source_case=models.F("target_case")),
                name="case_rel_no_self",
            ),
            models.UniqueConstraint(
                fields=["target_case"],
                condition=models.Q(relationship_type=CaseRelationshipType.PARENT_OF),
                name="case_rel_one_parent",
            ),
            models.UniqueConstraint(
                fields=["source_case"],
                condition=models.Q(relationship_type=CaseRelationshipType.DUPLICATE_OF),
                name="case_rel_one_duplicate_target",
            ),
        ]
        indexes = [
            models.Index(fields=["source_case", "relationship_type"], name="case_rel_source_type_idx"),
            models.Index(fields=["target_case", "relationship_type"], name="case_rel_target_type_idx"),
        ]

    def __str__(self):
        return f"{self.source_case.case_id} {self.relationship_type} {self.target_case.case_id}"
