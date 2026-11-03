import re

from apps.agentic.analysis.schemas import AttackChainStep, EvidenceFinding, TimelineEvent
from apps.agentic.multiagent.agents.base import BaseAgent
from apps.agentic.multiagent.schemas import InvestigationResult, MitreTechnique

MAX_SEARCHES = 3
TECHNIQUE_RE = re.compile(r"(T\d{4}(?:\.\d{3})?)\s*[-:]?\s*(.*)")

# Keyword -> ATT&CK mapping used when alerts carry no explicit technique.
KEYWORD_TECHNIQUES = [
    (("vssadmin", "shadow"), ("Impact", "T1490", "Inhibit System Recovery")),
    (("encrypt", "ransom"), ("Impact", "T1486", "Data Encrypted for Impact")),
    (("powershell",), ("Execution", "T1059.001", "PowerShell")),
    (("phish", "attachment"), ("Initial Access", "T1566", "Phishing")),
    (("attachuserpolicy", "iam policy"), ("Privilege Escalation", "T1098", "Account Manipulation")),
    (("brute", "failed login", "password spray"), ("Credential Access", "T1110", "Brute Force")),
    (("valid account", "console login"), ("Defense Evasion", "T1078", "Valid Accounts")),
    (("beacon", "c2"), ("Command and Control", "T1071", "Application Layer Protocol")),
]
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def _tactic_rank(tactic):
    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)


class InvestigationAgent(BaseAgent):
    key = "investigation"
    name = "Investigation Agent"
    description = "Searches logs around key entities, reconstructs the attack timeline and chain, and maps behaviour to MITRE ATT&CK."
    tools = ("siem.search",)
    output_schema = InvestigationResult

    def gather(self, ctx, toolbox):
        pivots = []
        for group in (ctx.host_artifacts(), ctx.identity_artifacts(), ctx.ioc_artifacts()):
            if group:
                pivots.append(group[0]["value"])
        searches = []
        for value in pivots[:MAX_SEARCHES]:
            out = toolbox.log_search(value) or {"source": "error", "results": []}
            searches.append({"pivot": value, "source": out["source"], "hits": len(out["results"]), "sample": out["results"][:3]})
        return {"log_searches": searches}

    def offline(self, ctx, evidence):
        alerts = sorted(ctx.alerts(), key=lambda a: str(a.get("first_seen_time") or ""))
        techniques = {}
        for alert in alerts:
            match = TECHNIQUE_RE.match(str(alert.get("technique") or ""))
            if match:
                tid, name = match.group(1), match.group(2) or alert.get("technique")
                techniques[tid] = MitreTechnique(tactic=alert.get("tactic") or "Unknown", technique_id=tid, name=name.strip(), evidence=alert.get("title", ""))
        text = ctx.text_blob()
        for keywords, (tactic, tid, name) in KEYWORD_TECHNIQUES:
            if tid not in techniques and any(k in text for k in keywords):
                techniques[tid] = MitreTechnique(tactic=tactic, technique_id=tid, name=name, evidence=f"Keyword match: {', '.join(k for k in keywords if k in text)}")
        mitre = sorted(techniques.values(), key=lambda t: _tactic_rank(t.tactic))

        timeline = [
            TimelineEvent(
                timestamp=str(a.get("first_seen_time") or a.get("created_at") or ""),
                attack_behavior=a.get("title", ""),
                evidence_field=f"alert.rule_name={a.get('rule_name', '')}",
            )
            for a in alerts
        ]
        chain = [AttackChainStep(attack_stage=t.tactic, description=f"{t.technique_id} {t.name}") for t in mitre]

        findings = [
            EvidenceFinding(
                title=a.get("title", "Alert"),
                finding_type="detection",
                subject=a.get("rule_name", ""),
                evidence=str(a.get("desc", ""))[:300],
                conclusion=f"Source severity {a.get('severity')}, confidence {a.get('confidence')}.",
            )
            for a in alerts[:5]
        ]
        ti = ctx.findings.get("threat_intel") or {}
        for indicator in ti.get("indicators", []):
            if indicator.get("reputation") == "malicious":
                findings.append(EvidenceFinding(
                    title=f"Malicious indicator {indicator['value']}",
                    finding_type="threat_intel",
                    subject=indicator["value"],
                    evidence=indicator.get("context", ""),
                    conclusion="Indicator is known-bad in threat intelligence.",
                ))
        log_hits = sum(s["hits"] for s in evidence.get("log_searches", []))

        triage = ctx.findings.get("triage") or {}
        verdict = triage.get("verdict", "Suspicious")
        confidence = int(triage.get("confidence_score", 50))
        malicious = int(ti.get("malicious_count", 0) or 0)
        if malicious and verdict in ("Suspicious", "Insufficient Data"):
            verdict = "True Positive"
        confidence = min(95, confidence + 8 * min(malicious, 2) + (5 if len(mitre) >= 2 else 0) + (3 if log_hits else 0))

        assets = ctx.findings.get("asset_context") or {}
        scope_entities = [e["name"] for e in assets.get("entities", [])] or [a["value"] for a in ctx.host_artifacts() + ctx.identity_artifacts()]
        narrative = (
            f"{triage.get('classification', 'Activity')} observed across {len(alerts)} alert(s). "
            + (f"Behaviour maps to {', '.join(t.technique_id + ' ' + t.name for t in mitre)}. " if mitre else "")
            + (f"{malicious} indicator(s) are confirmed malicious by threat intel. " if malicious else "")
            + f"Log pivots returned {log_hits} related event(s)."
        )
        unknowns = []
        if not log_hits:
            unknowns.append("No additional log telemetry found beyond the triggering alerts.")
        if not malicious and ctx.ioc_artifacts():
            unknowns.append("External indicators have no known-bad reputation; attribution unconfirmed.")
        unknowns.append("Whether the activity succeeded beyond the observed step is not confirmed.")

        return InvestigationResult(
            attack_narrative=narrative,
            verdict=verdict,
            confidence_score=confidence,
            mitre_techniques=mitre,
            attack_chain=chain,
            attack_timeline=timeline,
            evidence_findings=findings,
            scope=f"Entities in scope: {', '.join(scope_entities[:8]) or 'not determined'}.",
            unknowns=unknowns,
        )

    def summarize(self, output):
        return output.attack_narrative
