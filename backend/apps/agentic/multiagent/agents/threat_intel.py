import logging

from apps.agentic.multiagent.agents.base import BaseAgent
from apps.agentic.multiagent.schemas import IndicatorAssessment, ThreatIntelResult
from apps.enrichments.models import Enrichment, EnrichmentProvider, EnrichmentType

logger = logging.getLogger(__name__)

MAX_INDICATORS = 8
RISK_TO_REPUTATION = {"high": "malicious", "medium": "suspicious", "low": "clean"}


def _compact(ti_output):
    """Keep only what an LLM needs from a provider response."""
    if not ti_output:
        return None
    results = []
    for r in ti_output.get("results", []):
        results.append({
            "provider": r.get("provider"),
            "risk_level": r.get("risk_level"),
            "reputation_score": r.get("reputation_score"),
            "is_malicious": r.get("is_malicious"),
            "tags": (r.get("tags") or [])[:8],
            "malware_families": (r.get("malware_families") or [])[:5],
            "adversaries": (r.get("adversaries") or [])[:5],
            "attack_techniques": (r.get("attack_techniques") or [])[:5],
        })
    return {"aggregated_risk_level": ti_output.get("aggregated_risk_level"), "results": results, "errors": ti_output.get("errors", [])}


class ThreatIntelAgent(BaseAgent):
    key = "threat_intel"
    name = "Threat Intel Agent"
    description = "Enriches IOCs (IPs, domains, URLs, hashes, emails) against threat-intelligence feeds and judges their reputation."
    tools = ("threat_intel.lookup",)
    output_schema = ThreatIntelResult

    def gather(self, ctx, toolbox):
        lookups = []
        for artifact in ctx.ioc_artifacts()[:MAX_INDICATORS]:
            out = toolbox.threat_intel_lookup(artifact["value"], artifact["type"])
            lookups.append({"indicator": artifact["value"], "type": artifact["type"], "intel": _compact(out)})
        return {"lookups": lookups}

    def offline(self, ctx, evidence):
        indicators = []
        campaigns = set()
        for item in evidence.get("lookups", []):
            intel = item.get("intel") or {}
            risk = intel.get("aggregated_risk_level")
            reputation = RISK_TO_REPUTATION.get(risk, "unknown")
            sources = [r["provider"] for r in intel.get("results", []) if r.get("provider")]
            tags = sorted({t for r in intel.get("results", []) for t in r.get("tags", [])})
            for r in intel.get("results", []):
                campaigns.update(r.get("malware_families", []) + r.get("adversaries", []))
            indicators.append(IndicatorAssessment(
                value=item["indicator"],
                indicator_type=item["type"],
                reputation=reputation,
                sources=sources,
                context=f"Feed risk={risk or 'unknown'}" + (f", tags: {', '.join(tags)}" if tags else ""),
            ))
        malicious = sum(1 for i in indicators if i.reputation == "malicious")
        suspicious = sum(1 for i in indicators if i.reputation == "suspicious")
        overall = "High" if malicious else "Medium" if suspicious else "Low" if indicators else "Informational"
        summary = (
            f"Checked {len(indicators)} indicator(s): {malicious} malicious, {suspicious} suspicious."
            if indicators else "No external indicators to enrich in this case."
        )
        return ThreatIntelResult(
            indicators=indicators,
            overall_risk=overall,
            malicious_count=malicious,
            known_campaigns=sorted(campaigns),
            summary=summary,
        )

    def confidence(self, output):
        return None

    def apply(self, ctx, output, *, run, step):
        for indicator in output.indicators:
            if indicator.reputation not in ("malicious", "suspicious"):
                continue
            try:
                Enrichment.objects.update_or_create(
                    case=ctx.case,
                    uid=f"agent-ti:{indicator.value}",
                    defaults={
                        "name": f"Threat Intel: {indicator.value}",
                        "type": EnrichmentType.THREAT_INTELLIGENCE,
                        "provider": EnrichmentProvider.SOC,
                        "value": indicator.value[:500],
                        "desc": f"{indicator.reputation.title()} - {indicator.context}"[:2000],
                        "data": indicator.model_dump(),
                    },
                )
            except Exception:
                logger.exception("Failed to store threat intel enrichment for %s", indicator.value)
