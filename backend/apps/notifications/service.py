"""Email the SOC when the AI agent team confirms something malicious or suspicious."""

import logging
from html import escape

from django.conf import settings
from django.core.mail import EmailMultiAlternatives

from apps.agentic.models import AgentRun

from .models import NotificationChannel, NotificationLog, NotificationStatus

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"Unknown": 0, "Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_SEVERITY_COLOUR = {"Critical": "#c62828", "High": "#ef6c00", "Medium": "#f9a825", "Low": "#2e7d32"}


def alert_recipients():
    return [address for address in settings.ALERT_EMAIL_TO if address]


def should_notify(verdict, severity):
    if verdict not in settings.ALERT_EMAIL_VERDICTS:
        return False
    return SEVERITY_RANK.get(severity or "Unknown", 0) >= SEVERITY_RANK.get(settings.ALERT_EMAIL_MIN_SEVERITY, 3)


def _already_sent(case, verdict, severity):
    """Skip if this case was already emailed with the same verdict at the same or higher severity."""
    previous = NotificationLog.objects.filter(
        case=case, channel=NotificationChannel.EMAIL, status=NotificationStatus.SENT, verdict=verdict
    ).values_list("severity", flat=True)
    current = SEVERITY_RANK.get(severity, 0)
    return any(SEVERITY_RANK.get(sent, 0) >= current for sent in previous)


def case_url(case):
    return f"{settings.SOC_CONSOLE_URL.rstrip('/')}/cases/{case.pk}"


def _latest_alert(case):
    return case.alerts.order_by("-created_at").first()


def build_case_email(case, *, verdict, severity, summary="", report=None):
    report = report or {}
    alert = _latest_alert(case)
    reference = case.case_id or str(case.pk)
    subject = f"[NEXUS-SOC][{severity or 'Unknown'}] {verdict}: {case.title}"[:300]

    details = [
        ("Case", reference),
        ("Verdict", verdict),
        ("Severity", severity or "Unknown"),
        ("Confidence", report.get("confidence") or case.confidence_ai or case.confidence or "Unknown"),
    ]
    if alert is not None:
        details += [
            ("Detection", alert.rule_name or alert.rule_id or alert.title),
            ("MITRE ATT&CK", " / ".join(v for v in (alert.tactic, alert.technique) if v) or "n/a"),
            ("Source", alert.product_name or "n/a"),
            ("First seen", alert.first_seen_time.isoformat() if alert.first_seen_time else "n/a"),
            ("Last seen", alert.last_seen_time.isoformat() if alert.last_seen_time else "n/a"),
        ]

    assets = [f"{a.get('asset_type', '')}: {a.get('asset_value', '')}" for a in report.get("affected_assets", [])][:8]
    if not assets and alert is not None:
        assets = [f"{a.type}: {a.value}" for a in alert.artifacts.all()[:8]]
    iocs = [f"{i.get('indicator_type', '')}: {i.get('value', '')}" + (f" ({i['context']})" if i.get("context") else "") for i in report.get("ioc_indicators", [])][:10]
    actions = [f"{r.get('action_type', '')}: {r.get('description', '')}" for r in report.get("remediations", [])][:10]
    if not actions and alert is not None and alert.mitigation:
        actions = [alert.mitigation]
    summary = summary or report.get("executive_summary") or case.description
    link = case_url(case)

    # Plain text
    lines = ["NEXUS-SOC security alert", "=" * 24, ""]
    lines += [f"{label}: {value}" for label, value in details]
    lines += ["", "Summary", "-------", summary or "n/a"]
    for heading, items in (("Affected assets", assets), ("Indicators of compromise", iocs), ("Recommended actions", actions)):
        if items:
            lines += ["", heading, "-" * len(heading), *[f"- {item}" for item in items]]
    lines += ["", f"Open the case: {link}", "", "This message was sent automatically by NEXUS-SOC."]
    text_body = "\n".join(lines)

    # HTML
    colour = _SEVERITY_COLOUR.get(severity, "#455a64")
    rows = "".join(
        f'<tr><td style="padding:4px 12px 4px 0;color:#607d8b;white-space:nowrap">{escape(label)}</td>'
        f'<td style="padding:4px 0">{escape(str(value))}</td></tr>'
        for label, value in details
    )

    def _section(heading, items):
        if not items:
            return ""
        return f'<h3 style="margin:20px 0 6px;font-size:15px">{escape(heading)}</h3><ul style="margin:0;padding-left:20px">' + "".join(
            f"<li style=\"margin:2px 0\">{escape(item)}</li>" for item in items
        ) + "</ul>"

    html_body = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:24px;background:#f4f6f8;font-family:Segoe UI,Arial,sans-serif;color:#1c2833">
<div style="max-width:640px;margin:auto;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #dde3e8">
  <div style="background:{colour};color:#fff;padding:16px 24px">
    <div style="font-size:12px;letter-spacing:1px;opacity:.9">NEXUS-SOC SECURITY ALERT</div>
    <div style="font-size:19px;font-weight:600;margin-top:4px">{escape(verdict)} &middot; {escape(severity or 'Unknown')}</div>
  </div>
  <div style="padding:20px 24px">
    <h2 style="margin:0 0 14px;font-size:17px">{escape(case.title)}</h2>
    <table style="border-collapse:collapse;font-size:14px">{rows}</table>
    <h3 style="margin:20px 0 6px;font-size:15px">Summary</h3>
    <p style="margin:0;line-height:1.5;font-size:14px">{escape(summary or 'n/a')}</p>
    {_section("Affected assets", assets)}
    {_section("Indicators of compromise", iocs)}
    {_section("Recommended actions", actions)}
    <p style="margin:24px 0 4px"><a href="{escape(link)}" style="background:#1565c0;color:#fff;text-decoration:none;padding:10px 18px;border-radius:5px;display:inline-block">Open case in NEXUS-SOC</a></p>
  </div>
  <div style="padding:12px 24px;background:#fafbfc;color:#90a4ae;font-size:12px">Sent automatically by NEXUS-SOC.</div>
</div></body></html>"""
    return subject, text_body, html_body


def send_case_email(case, *, verdict, severity, summary="", report=None, agent_run=None, recipients=None):
    recipients = recipients or alert_recipients()
    subject, text_body, html_body = build_case_email(case, verdict=verdict, severity=severity, summary=summary, report=report)
    log = NotificationLog(
        case=case,
        agent_run=agent_run,
        channel=NotificationChannel.EMAIL,
        verdict=verdict,
        severity=severity or "",
        recipients=recipients,
        subject=subject,
    )
    try:
        message = EmailMultiAlternatives(subject, text_body, settings.DEFAULT_FROM_EMAIL, recipients)
        message.attach_alternative(html_body, "text/html")
        message.send(fail_silently=False)
        log.status = NotificationStatus.SENT
        logger.info("Alert email sent for case %s to %s", case.pk, ", ".join(recipients))
    except Exception as exc:
        log.status = NotificationStatus.FAILED
        log.error = f"{type(exc).__name__}: {exc}"[:2000]
        logger.error("Alert email for case %s failed: %s", case.pk, log.error)
    log.save()
    return log


def notify_case_verdict(run):
    """Called when an agent run completes. Returns the NotificationLog or None if nothing was sent."""
    if not settings.ALERT_EMAIL_ENABLED:
        return None
    recipients = alert_recipients()
    if not recipients:
        return None
    case = run.case
    verdict = run.final_verdict or case.verdict_ai or ""
    severity = run.final_severity or case.severity_ai or case.severity or ""
    if not should_notify(verdict, severity) or _already_sent(case, verdict, severity):
        return None
    return send_case_email(
        case,
        verdict=verdict,
        severity=severity,
        summary=run.summary,
        report=run.report if isinstance(run.report, dict) else {},
        agent_run=run if isinstance(run, AgentRun) else None,
        recipients=recipients,
    )
