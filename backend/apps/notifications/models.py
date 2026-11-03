from django.db import models
from django.utils import timezone


class NotificationChannel(models.TextChoices):
    EMAIL = "email", "Email"


class NotificationStatus(models.TextChoices):
    SENT = "sent", "Sent"
    FAILED = "failed", "Failed"


class NotificationLog(models.Model):
    """One alert notification attempt, used for auditing and to avoid duplicate emails."""

    case = models.ForeignKey("cases.Case", on_delete=models.CASCADE, related_name="notifications")
    agent_run = models.ForeignKey("agentic.AgentRun", null=True, blank=True, on_delete=models.SET_NULL, related_name="notifications")
    channel = models.CharField(max_length=20, choices=NotificationChannel, default=NotificationChannel.EMAIL)
    status = models.CharField(max_length=20, choices=NotificationStatus)
    verdict = models.CharField(max_length=30, blank=True, default="")
    severity = models.CharField(max_length=20, blank=True, default="")
    recipients = models.JSONField(default=list, blank=True)
    subject = models.CharField(max_length=500, blank=True, default="")
    error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "notification_logs"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["case", "channel", "status"], name="notif_case_channel_idx")]

    def __str__(self):
        return f"{self.channel} {self.status} for {self.case_id}: {self.subject}"
