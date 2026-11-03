from django.utils import timezone

from apps.agentic.analysis.schemas import AffectedAsset, AnalysisRecord, IndicatorOfCompromise, InvestigationReport, Remediation
from apps.agentic.multiagent.agents.base import BaseAgent
from apps.agentic.multiagent.schemas import FinalReport
from apps.agentic.services.cases import save_case_analysis_record

PROFILE_VERSION = "multi-agent-2026-11"
RISK_TO_PRIORITY = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}


def confidence_label(score):
    if score is None:
        return "Medium"
    return "High" if score >= 75 else "Medium" if score >= 50 else "Low"


class ReportingAgent(BaseAgent):
    key = "reporting"
    name = "Reporting Agent"
    description = "Consolidates every agent's findings into the final verdict, an executive summary and a technical incident report."
    tools = ()
    output_schema = FinalReport

    def offline(self, ctx, evidence):
        f = ctx.findings
        triage = f.get("triage") or {}
        inv = f.get("investigation") or {}
        ti = f.get("threat_intel") or {}
        assets = f.get("asset_context") or {}
        response = f.get("response") or {}

        verdict = inv.get("verdict") or triage.get("verdict") or "Insufficient Data"
        score = inv.get("confidence_score", triage.get("confidence_score"))
        severity = triage.get("severity", "Medium")
        if verdict in ("False Positive", "Benign"):
            severity = "Low" if severity not in ("Informational",) else severity
        impact = assets.get("highest_criticality") or "Unknown"
        if verdict in ("False Positive", "Benign"):
            impact = "Low"
        priority = triage.get("priority", severity)
        priority = "Low" if priority == "Informational" else priority

        affected = [AffectedAsset(asset_type=e.get("entity_type", "other"), asset_value=e["name"]) for e in assets.get("entities", [])]
        if not affected:
            affected = [AffectedAsset(asset_type=a["type"], asset_value=a["value"]) for a in (ctx.host_artifacts() + ctx.identity_artifacts())[:6]]
        iocs = [
            IndicatorOfCompromise(indicator_type=i["indicator_type"], value=i["value"], context=i.get("context", ""))
            for i in ti.get("indicators", [])
            if i.get("reputation") in ("malicious", "suspicious")
        ]
        remediations = [
            Remediation(action_type=a["action_type"], description=f"{a['target']}: {a['rationale']}", priority=priority)
            for a in response.get("actions", [])
        ]
        techniques = ", ".join(t["technique_id"] for t in inv.get("mitre_techniques", [])) or "no mapped techniques"
        title = ctx.payload.get("title", "this case")
        executive = (
            f"The AI SOC team assessed \"{title}\" as {verdict} with {confidence_label(score).lower()} confidence. "
            f"{triage.get('classification', 'The activity')} was observed with {severity.lower()} severity"
            + (f", affecting assets of up to {impact.lower()} business criticality" if impact not in ("Unknown",) else "")
            + ". "
            + (f"{len(iocs)} malicious or suspicious indicator(s) were identified. " if iocs else "")
            + (f"{len(remediations)} response action(s) were proposed; those above low risk await analyst approval." if remediations else "No containment actions are required.")
        )
        digest = f"{verdict} | {triage.get('classification', 'Activity')} | severity {severity} | ATT&CK: {techniques}"
        findings = inv.get("evidence_findings", [])
        return FinalReport(
            verdict=verdict,
            severity=severity,
            impact=impact if impact in ("Critical", "High", "Medium", "Low") else "Unknown",
            priority=priority,
            confidence=confidence_label(score),
            executive_summary=executive,
            digest=digest,
            affected_assets=affected,
            evidence_findings=findings,
            attack_chain=inv.get("attack_chain", []),
            attack_timeline=inv.get("attack_timeline", []),
            ioc_indicators=iocs,
            remediations=remediations,
            unknowns=inv.get("unknowns", []),
        )

    def summarize(self, output):
        return output.executive_summary

    def confidence(self, output):
        return {"High": 85, "Medium": 65, "Low": 40}.get(output.confidence)

    def apply(self, ctx, output, *, run, step):
        report_fields = output.model_dump(exclude={"executive_summary"})
        if report_fields.get("priority") == "Informational":
            report_fields["priority"] = "Low"
        record = AnalysisRecord(
            trigger=run.trigger or "agents",
            source_type="agentrun",
            source_id=str(run.pk),
            profile_version=PROFILE_VERSION,
            generated_at=timezone.now().isoformat(),
            report=InvestigationReport(**report_fields),
        )
        save_case_analysis_record(case=ctx.case, record=record)
