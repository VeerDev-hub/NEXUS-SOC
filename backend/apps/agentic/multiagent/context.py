"""Shared state ("blackboard") passed between agents during one run."""

import ipaddress
from dataclasses import dataclass, field

from apps.agentic.analysis.profiles import serialize_case_for_investigation
from apps.artifacts.models import Artifact, ArtifactType

IOC_TYPES = {
    ArtifactType.IP_ADDRESS,
    ArtifactType.URL_STRING,
    ArtifactType.UNIFORM_RESOURCE_LOCATOR,
    ArtifactType.HASH,
    ArtifactType.EMAIL_ADDRESS,
    ArtifactType.HOSTNAME,
}
HOST_TYPES = {ArtifactType.HOSTNAME, ArtifactType.ENDPOINT, ArtifactType.DEVICE}
IDENTITY_TYPES = {ArtifactType.USER_NAME, ArtifactType.USER, ArtifactType.ACCOUNT, ArtifactType.EMAIL_ADDRESS}
CLOUD_TYPES = {ArtifactType.RESOURCE_UID, ArtifactType.RESOURCE}

# Fields that are noise for agents and only cost tokens.
_DROP_CASE_KEYS = {"audit_logs"}


def is_private_ip(value):
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


@dataclass
class CaseContext:
    case: object
    payload: dict
    artifacts: list[dict]
    user_input: str = ""
    findings: dict = field(default_factory=dict)

    @classmethod
    def build(cls, case, *, user_input=""):
        payload = {k: v for k, v in serialize_case_for_investigation(case).items() if k not in _DROP_CASE_KEYS}
        artifacts = [
            {"type": a.type, "value": a.value, "role": a.role, "name": a.name}
            for a in Artifact.objects.filter(alerts__case=case).distinct().order_by("type", "value")
            if a.value
        ]
        return cls(case=case, payload=payload, artifacts=artifacts, user_input=user_input)

    # ---- artifact helpers -------------------------------------------------
    def artifacts_of(self, types):
        return [a for a in self.artifacts if a["type"] in types]

    def ioc_artifacts(self):
        return [a for a in self.artifacts_of(IOC_TYPES) if not (a["type"] == ArtifactType.IP_ADDRESS and is_private_ip(a["value"]))]

    def host_artifacts(self):
        hosts = self.artifacts_of(HOST_TYPES)
        hosts += [a for a in self.artifacts_of({ArtifactType.IP_ADDRESS}) if is_private_ip(a["value"])]
        return hosts

    def identity_artifacts(self):
        return self.artifacts_of(IDENTITY_TYPES)

    def cloud_artifacts(self):
        return self.artifacts_of(CLOUD_TYPES)

    def alerts(self):
        return self.payload.get("alerts") or []

    def text_blob(self):
        """Lower-cased text of the case, used by offline heuristics."""
        parts = [self.payload.get("title", ""), self.payload.get("description", ""), " ".join(self.payload.get("tags") or [])]
        for alert in self.alerts():
            parts += [
                str(alert.get("title", "")),
                str(alert.get("desc", "")),
                str(alert.get("rule_name", "")),
                " ".join(alert.get("labels") or []),
            ]
        parts += [a["value"] for a in self.artifacts]
        return " ".join(str(p) for p in parts).lower()

    def compact_case(self):
        return self.payload

    def agent_payload(self, evidence=None):
        data = {"case": self.compact_case(), "artifacts": self.artifacts, "prior_findings": self.findings}
        if evidence:
            data["evidence"] = evidence
        if self.user_input:
            data["analyst_input"] = self.user_input
        return data
