from django.db import models


class EntityType(models.TextChoices):
    USER = "user", "User"
    HOST = "host", "Host"


class EntityProfile(models.Model):
    """Learned behavioural baseline of one user or host (see ``apps.livedetect.baseline``).

    ``data`` holds bounded frequency tables, e.g. for a user::

        {"src_ips": {"10.0.0.5": 41}, "hosts": {"web-01": 40}, "hours": [0, 0, ..., 12, 9, ...],
         "logons": 41, "privilege": {"web-01": 3}}

    and for a host::

        {"processes": {"c:\\windows\\system32\\svchost.exe": 230}, "process_events": 230, "users": {...}}
    """

    entity_type = models.CharField(max_length=16, choices=EntityType.choices)
    entity = models.CharField(max_length=255)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    observations = models.PositiveIntegerField(default=0)
    data = models.JSONField(default=dict, blank=True)
    risk_score = models.FloatField(default=0)
    risk_updated_at = models.DateTimeField(null=True, blank=True)
    anomaly_count = models.PositiveIntegerField(default=0)
    last_anomaly_at = models.DateTimeField(null=True, blank=True)
    last_anomaly = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["entity_type", "entity"], name="uniq_entity_profile")]
        indexes = [models.Index(fields=["-risk_score"]), models.Index(fields=["-last_anomaly_at"])]
        ordering = ["-risk_score", "entity"]

    def __str__(self):
        return f"{self.entity_type}:{self.entity}"
