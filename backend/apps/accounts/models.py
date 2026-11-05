import secrets

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from .rbac import Role


def generate_api_key():
    return f"asp_{secrets.token_urlsafe(32)}"


class User(AbstractUser):
    class AuthType(models.TextChoices):
        LOCAL = "local", "Local Password"
        LDAP = "ldap", "LDAP"

    avatar_attachment = models.ForeignKey(
        "attachments.Attachment",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="avatar_users",
    )
    mobile_phone = models.CharField(max_length=20, blank=True, default="")
    auth_type = models.CharField(max_length=20, choices=AuthType.choices, default=AuthType.LOCAL)
    role = models.CharField(max_length=30, choices=Role.choices, default=Role.TIER1_ANALYST, db_index=True)
    title = models.CharField(max_length=100, blank=True, default="", help_text="Job title shown in the UI")
    notify_on_playbook_completion = models.BooleanField(default=True)
    notify_on_case_assignment = models.BooleanField(default=True, help_text="Inbox message and email when a case is assigned to this user")
    email_alerts = models.BooleanField(default=True, help_text="Email this user when the AI team confirms a High/Critical case")

    class Meta:
        db_table = "users"

    def __str__(self):
        return self.get_full_name() or self.username

    def save(self, *args, **kwargs):
        if self.is_superuser:
            self.role = Role.ADMIN
        return super().save(*args, **kwargs)

    @property
    def role_label(self):
        return Role(self.role).label if self.role in Role.values else self.role


class UserApiKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(max_length=100)
    key = models.CharField(max_length=128, unique=True, default=generate_api_key)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_api_keys"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.user})"

    @property
    def is_expired(self):
        return bool(self.expires_at and self.expires_at <= timezone.now())

    def refresh_key(self):
        self.key = generate_api_key()
        return self.key
