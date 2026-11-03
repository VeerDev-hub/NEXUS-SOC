from django.db import models
from django.db.models.functions import Coalesce

from apps.common.models import BaseModel
from apps.common.readable_ids import save_with_readable_id


def value_labeled(choice_class):
    for member in choice_class:
        member._label_ = member.value
    return choice_class


@value_labeled
class Severity(models.TextChoices):
    UNKNOWN = "Unknown"
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@value_labeled
class Confidence(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@value_labeled
class Impact(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@value_labeled
class Disposition(models.TextChoices):
    UNKNOWN = "Unknown"
    ALLOWED = "Allowed"
    BLOCKED = "Blocked"
    QUARANTINED = "Quarantined"
    ISOLATED = "Isolated"
    DELETED = "Deleted"
    DROPPED = "Dropped"
    CUSTOM_ACTION = "Custom Action"
    APPROVED = "Approved"
    RESTORED = "Restored"
    EXONERATED = "Exonerated"
    CORRECTED = "Corrected"
    PARTIALLY_CORRECTED = "Partially Corrected"
    UNCORRECTED = "Uncorrected"
    DELAYED = "Delayed"
    DETECTED = "Detected"
    NO_ACTION = "No Action"
    LOGGED = "Logged"
    TAGGED = "Tagged"
    ALERT = "Alert"
    COUNT = "Count"
    RESET = "Reset"
    CAPTCHA = "Captcha"
    CHALLENGE = "Challenge"
    ACCESS_REVOKED = "Access Revoked"
    REJECTED = "Rejected"
    UNAUTHORIZED = "Unauthorized"
    ERROR = "Error"
    OTHER = "Other"


@value_labeled
class AlertAction(models.TextChoices):
    UNKNOWN = "Unknown"
    ALLOWED = "Allowed"
    DENIED = "Denied"
    OBSERVED = "Observed"
    MODIFIED = "Modified"
    OTHER = "Other"


@value_labeled
class AlertAnalyticType(models.TextChoices):
    UNKNOWN = "Unknown"
    RULE = "Rule"
    BEHAVIORAL = "Behavioral"
    STATISTICAL = "Statistical"
    LEARNING = "Learning (ML/DL)"
    FINGERPRINTING = "Fingerprinting"
    TAGGING = "Tagging"
    KEYWORD_MATCH = "Keyword Match"
    REGULAR_EXPRESSIONS = "Regular Expressions"
    EXACT_DATA_MATCH = "Exact Data Match"
    PARTIAL_DATA_MATCH = "Partial Data Match"
    INDEXED_DATA_MATCH = "Indexed Data Match"
    OTHER = "Other"


@value_labeled
class AlertAnalyticState(models.TextChoices):
    UNKNOWN = "Unknown"
    ACTIVE = "Active"
    SUPPRESSED = "Suppressed"
    EXPERIMENTAL = "Experimental"
    OTHER = "Other"


@value_labeled
class ProductCategory(models.TextChoices):
    DLP = "DLP"
    EMAIL = "Email"
    OT = "OT"
    PROXY = "Proxy"
    UEBA = "UEBA"
    TI = "ThreatIntelligence"
    IAM = "IAM"
    EDR = "EDR"
    NDR = "NDR"
    CLOUD = "Cloud"
    SIEM = "SIEM"
    WAF = "WAF"
    OTHER = "Other"


@value_labeled
class AlertPolicyType(models.TextChoices):
    IDENTITY_POLICY = "Identity Policy"
    RESOURCE_POLICY = "Resource Policy"
    SERVICE_CONTROL_POLICY = "Service Control Policy"
    ACCESS_CONTROL_POLICY = "Access Control Policy"
    OTHER = "Other"


@value_labeled
class AlertRiskLevel(models.TextChoices):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    OTHER = "Other"


@value_labeled
class AlertStatus(models.TextChoices):
    UNKNOWN = "Unknown"
    NEW = "New"
    IN_PROGRESS = "In Progress"
    SUPPRESSED = "Suppressed"
    RESOLVED = "Resolved"
    ARCHIVED = "Archived"
    DELETED = "Deleted"
    OTHER = "Other"


@value_labeled
class AlertTactic(models.TextChoices):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class Alert(BaseModel):
    alert_id = models.CharField(max_length=32, unique=True, editable=False, db_index=True, blank=True, default="", help_text="Record ID e.g. alert_000001, auto-generated, no manual input needed")
    case = models.ForeignKey("cases.Case", on_delete=models.CASCADE, related_name="alerts", help_text="Linked case id, reverse association, auto-linked, no manual setting needed")
    title = models.CharField(max_length=500, blank=True, default="", help_text="Alert title")
    severity = models.CharField(max_length=20, choices=Severity, default=Severity.UNKNOWN, help_text="Source-defined severity")
    confidence = models.CharField(max_length=20, choices=Confidence, default=Confidence.UNKNOWN, help_text="True-positive confidence")
    impact = models.CharField(max_length=20, choices=Impact, default=Impact.UNKNOWN, help_text="Potential impact")
    disposition = models.CharField(max_length=20, choices=Disposition, default=Disposition.UNKNOWN, help_text="Source disposition")
    action = models.CharField(max_length=20, choices=AlertAction, default=AlertAction.UNKNOWN, help_text="Observed action")
    labels = models.JSONField(default=list, blank=True, help_text="Alert labels")
    desc = models.TextField(blank=True, default="", help_text="Alert description")
    first_seen_time = models.DateTimeField(null=True, blank=True, help_text="First observed time")
    last_seen_time = models.DateTimeField(null=True, blank=True, help_text="Last observed time")
    rule_id = models.CharField(max_length=255, blank=True, default="", help_text="SIEM rule ID")
    rule_name = models.CharField(max_length=255, blank=True, default="", help_text="SIEM rule name")
    correlation_uid = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Case correlation ID, alerts with the same correlation_uid are linked to the same event")
    src_url = models.URLField(max_length=500, blank=True, default="", help_text="Source alert URL")
    source_uid = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Source product ID, can be used to locate the unique alert in the source system")
    data_sources = models.JSONField(default=list, blank=True, help_text="Underlying data sources")
    analytic_name = models.CharField(max_length=255, blank=True, default="", help_text="Analytic engine name")
    analytic_type = models.CharField(max_length=30, choices=AlertAnalyticType, default=AlertAnalyticType.UNKNOWN, help_text="Analytic engine type")
    analytic_state = models.CharField(max_length=20, choices=AlertAnalyticState, blank=True, default="", help_text="Analytic rule state")
    analytic_desc = models.TextField(blank=True, default="", help_text="Analytic rule description")
    tactic = models.CharField(max_length=100, choices=AlertTactic, blank=True, default="", help_text="Mapped MITRE tactic")
    technique = models.CharField(max_length=100, blank=True, default="", help_text="Mapped MITRE technique")
    sub_technique = models.CharField(max_length=100, blank=True, default="", help_text="Mapped MITRE sub-technique")
    mitigation = models.TextField(blank=True, default="", help_text="Suggested mitigation")
    product_category = models.CharField(max_length=30, choices=ProductCategory, blank=True, default="", help_text="Source product category")
    product_vendor = models.CharField(max_length=255, blank=True, default="", help_text="Source vendor")
    product_name = models.CharField(max_length=255, blank=True, default="", help_text="Source product name")
    product_feature = models.CharField(max_length=255, blank=True, default="", help_text="Source product feature")
    policy_name = models.CharField(max_length=255, blank=True, default="", help_text="Trigger policy name")
    policy_type = models.CharField(max_length=30, choices=AlertPolicyType, blank=True, default="", help_text="Trigger policy type")
    policy_desc = models.TextField(blank=True, default="", help_text="Trigger policy description")
    risk_level = models.CharField(max_length=20, choices=AlertRiskLevel, blank=True, default="", help_text="Assessed risk level")
    status = models.CharField(max_length=20, choices=AlertStatus, default=AlertStatus.NEW, help_text="Alert handling status")
    status_detail = models.TextField(blank=True, default="", help_text="Handling status details")
    remediation = models.TextField(blank=True, default="", help_text="Remediation advice or record")
    unmapped = models.JSONField(default=dict, blank=True, help_text="Raw unmapped fields, JSON Format")
    raw_data = models.JSONField(default=dict, blank=True, help_text="Raw alert log JSON")

    # M2M
    artifacts = models.ManyToManyField("artifacts.Artifact", related_name="alerts", blank=True, help_text="Extracted artifacts")

    def save(self, *args, **kwargs):
        return save_with_readable_id(self, "alert_id", "alert", *args, **kwargs)

    class Meta:
        db_table = "alerts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "-id"], name="alert_created_id_idx"),
            models.Index(fields=["-first_seen_time", "-id"], name="alert_first_seen_id_idx"),
            models.Index(
                Coalesce("last_seen_time", "first_seen_time", "created_at"),
                name="alert_event_time_idx",
            ),
        ]

    def __str__(self):
        return self.title or str(self.id)
