import logging

from apps.agentic.multiagent.agents.base import BaseAgent
from apps.agentic.multiagent.schemas import AssetContextResult, EntityContext
from apps.artifacts.models import ArtifactType
from apps.enrichments.models import Enrichment, EnrichmentProvider, EnrichmentType

logger = logging.getLogger(__name__)

MAX_ENTITIES = 8
CRIT_ORDER = ["Unknown", "Low", "Medium", "High", "Critical"]


def _entity_type(artifact_type, record_type):
    if record_type == "identity" or artifact_type in (ArtifactType.USER_NAME, ArtifactType.USER, ArtifactType.ACCOUNT):
        return "user"
    if record_type == "mailbox" or artifact_type in (ArtifactType.EMAIL_ADDRESS, ArtifactType.EMAIL):
        return "mailbox"
    if record_type == "resource" or artifact_type in (ArtifactType.RESOURCE_UID, ArtifactType.RESOURCE):
        return "cloud_resource"
    if record_type == "asset":
        return "host"
    return "other"


def _compact(cmdb_output):
    if not cmdb_output:
        return None
    for r in cmdb_output.get("results", []):
        if r.get("supported"):
            return {
                "record_type": r.get("record_type"),
                "asset": {k: r.get("asset", {}).get(k) for k in ("asset_type", "hostname", "environment", "network_zone", "status")} if r.get("asset") else {},
                "identity": {k: r.get("identity", {}).get(k) for k in ("display_name", "department", "job_title", "privilege_level")} if r.get("identity") else {},
                "resource": r.get("resource") or {},
                "business": {k: r.get("business", {}).get(k) for k in ("service_name", "business_criticality", "department", "environment")},
                "owner": r.get("owner") or {},
            }
    return {"record_type": None, "errors": cmdb_output.get("errors", [])}


class AssetContextAgent(BaseAgent):
    key = "asset_context"
    name = "Asset & Identity Agent"
    description = "Looks up affected hosts, users and cloud resources in the CMDB to judge business criticality, ownership and blast radius."
    tools = ("cmdb.lookup",)
    output_schema = AssetContextResult

    def gather(self, ctx, toolbox):
        targets = (ctx.host_artifacts() + ctx.identity_artifacts() + ctx.cloud_artifacts())[:MAX_ENTITIES]
        lookups = []
        seen = set()
        for artifact in targets:
            if artifact["value"] in seen:
                continue
            seen.add(artifact["value"])
            out = toolbox.cmdb_lookup(artifact["type"], artifact["value"])
            lookups.append({"value": artifact["value"], "type": artifact["type"], "role": artifact["role"], "context": _compact(out)})
        return {"lookups": lookups}

    def offline(self, ctx, evidence):
        entities = []
        for item in evidence.get("lookups", []):
            context = item.get("context") or {}
            business = context.get("business") or {}
            identity = context.get("identity") or {}
            criticality = business.get("business_criticality") or "Unknown"
            if identity.get("privilege_level") in ("Privileged", "High/Critical") and CRIT_ORDER.index(criticality if criticality in CRIT_ORDER else "Unknown") < 3:
                criticality = "High"
            notes = []
            if business.get("service_name"):
                notes.append(f"Supports {business['service_name']} ({business.get('environment', '?')})")
            if identity.get("privilege_level"):
                notes.append(f"Privilege: {identity['privilege_level']}")
            entities.append(EntityContext(
                name=item["value"],
                entity_type=_entity_type(item["type"], context.get("record_type")),
                criticality=criticality if criticality in CRIT_ORDER else "Unknown",
                owner=(context.get("owner") or {}).get("owner_team", ""),
                business_unit=business.get("department", ""),
                notes="; ".join(notes),
            ))
        highest = max((e.criticality for e in entities), key=CRIT_ORDER.index, default="Unknown")
        crit_entities = [e.name for e in entities if e.criticality in ("Critical", "High")]
        blast = (
            f"High-value entities involved: {', '.join(crit_entities)}. Compromise could affect their dependent services."
            if crit_entities else "No high-criticality assets identified; impact appears contained to the listed entities."
        )
        return AssetContextResult(
            entities=entities,
            highest_criticality=highest,
            blast_radius=blast,
            summary=f"Profiled {len(entities)} entit{'y' if len(entities) == 1 else 'ies'}; highest business criticality {highest}.",
        )

    def confidence(self, output):
        return None

    def apply(self, ctx, output, *, run, step):
        for entity in output.entities:
            try:
                Enrichment.objects.update_or_create(
                    case=ctx.case,
                    uid=f"agent-cmdb:{entity.name}",
                    defaults={
                        "name": f"Asset context: {entity.name}",
                        "type": EnrichmentType.IDENTITY if entity.entity_type == "user" else EnrichmentType.CMDB,
                        "provider": EnrichmentProvider.INTERNAL_CMDB,
                        "value": entity.name[:500],
                        "desc": f"Criticality {entity.criticality}; owner {entity.owner or 'unknown'}. {entity.notes}"[:2000],
                        "data": entity.model_dump(),
                    },
                )
            except Exception:
                logger.exception("Failed to store asset enrichment for %s", entity.name)
