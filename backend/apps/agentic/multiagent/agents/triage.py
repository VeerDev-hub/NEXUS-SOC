from apps.agentic.multiagent.agents.base import BaseAgent
from apps.agentic.multiagent.schemas import TriageResult

LEVEL_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

CATEGORY_RULES = [
    (("vssadmin", "shadow", "ransomware", "encrypt"), "Ransomware precursor"),
    (("phish", "suspicious email", "reported email", "sender"), "Phishing"),
    (("attachuserpolicy", "iam", "privilege escalation", "assumerole"), "Cloud privilege escalation"),
    (("brute", "failed login", "password spray", "authentication failure"), "Brute-force / credential attack"),
    (("malware", "trojan", "beacon", "c2", "command and control"), "Malware / C2 activity"),
    (("exfil", "dlp", "upload"), "Data exfiltration"),
    (("scan", "recon", "port sweep"), "Reconnaissance"),
]
FALSE_POSITIVE_HINTS = ("test", "pentest", "authorized", "simulation", "scanner", "whitelist", "known benign", "red team")


def _level(value):
    value = (value or "").strip().title()
    return value if value in LEVEL_ORDER else None


def _max_level(values, default="Low"):
    levels = [lv for lv in (_level(v) for v in values) if lv]
    return max(levels, key=LEVEL_ORDER.index) if levels else default


class TriageAgent(BaseAgent):
    key = "triage"
    name = "Triage Agent"
    description = "Classifies the alert, scores severity and priority, and screens for false positives and duplicates."
    tools = ("cases.related", "knowledge.search")
    output_schema = TriageResult

    def gather(self, ctx, toolbox):
        values = [a["value"] for a in ctx.artifacts]
        keywords = [ctx.payload.get("title", ""), *(ctx.payload.get("tags") or [])]
        keywords += [alert.get("rule_name", "") for alert in ctx.alerts()]
        return {
            "related_cases": toolbox.related_cases(values) or [],
            "knowledge": toolbox.knowledge_search(keywords) or [],
        }

    def offline(self, ctx, evidence):
        text = ctx.text_blob()
        classification = next(
            (label for keywords, label in CATEGORY_RULES if any(k in text for k in keywords)),
            "Suspicious activity",
        )
        alert_severity = _max_level([a.get("severity") for a in ctx.alerts()] + [ctx.payload.get("severity")], "Medium")
        knowledge_text = " ".join(str(k.get("body", "")) + str(k.get("title", "")) for k in evidence.get("knowledge", [])).lower()
        fp_hits = [hint for hint in FALSE_POSITIVE_HINTS if hint in text or hint in knowledge_text]
        related = evidence.get("related_cases", [])
        duplicate = any(r.get("title") == ctx.payload.get("title") and r.get("status") not in ("Closed", "Resolved") for r in related)
        high_conf_alerts = any((a.get("confidence") or "").lower() == "high" for a in ctx.alerts())

        observations = [f"{len(ctx.alerts())} alert(s), highest source severity {alert_severity}."]
        observations.append(f"{len(ctx.artifacts)} artifact(s) extracted ({len(ctx.ioc_artifacts())} external IOC candidate(s)).")
        if related:
            observations.append(f"Shares indicators with {len(related)} other case(s): " + ", ".join(r["case_id"] for r in related))

        if fp_hits:
            verdict, confidence, severity = "False Positive", 80, "Low"
        elif alert_severity in ("Critical", "High") and high_conf_alerts:
            verdict, confidence, severity = "True Positive", 78, alert_severity
        elif alert_severity in ("Critical", "High", "Medium"):
            verdict, confidence, severity = "Suspicious", 60, alert_severity
        else:
            verdict, confidence, severity = "Insufficient Data", 40, alert_severity

        summary = (
            f"Classified as {classification}. Initial verdict {verdict} ({confidence}% confidence), severity {severity}."
            + (f" False-positive indicators: {', '.join(fp_hits)}." if fp_hits else "")
            + (" Possible duplicate of an open case." if duplicate else "")
        )
        return TriageResult(
            classification=classification,
            verdict=verdict,
            severity=severity,
            priority=severity,
            confidence_score=confidence,
            is_duplicate=duplicate,
            false_positive_indicators=fp_hits,
            key_observations=observations,
            summary=summary,
        )
