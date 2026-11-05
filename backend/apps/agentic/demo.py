"""Demo attack scenarios: realistic incidents generated on demand for presentations.

Where a real detection module exists (EDR, email, cloud) the scenario feeds it a
raw event exactly as a SIEM would, so the normal ingestion path creates the case,
alerts and artifacts. The agent team then picks the case up automatically.
"""

import importlib.util
import random
import uuid
from datetime import timedelta
from functools import lru_cache
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.agentic.services.alerts import create_alert_with_context
from apps.alerts.models import AlertAction, AlertAnalyticType, AlertStatus, Confidence, Disposition, Impact, ProductCategory, Severity
from apps.artifacts.models import ArtifactName, ArtifactRole, ArtifactType
from apps.cases.models import CaseConfidence, CaseImpact, CasePriority


@lru_cache(maxsize=8)
def _module(filename):
    path = Path(settings.CUSTOM_DIR) / "modules" / filename
    spec = importlib.util.spec_from_file_location(f"demo_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Module()


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _suffix():
    return f"{random.randint(10, 99)}"


# ---------------------------------------------------------------- scenarios ----

def ransomware():
    now = timezone.now()
    host = f"prod-web-{_suffix()}"
    user = random.choice(["admin_rkapoor", "admin_sjoshi", "admin_mdas"])
    first = _module("edr_vssadmin_delete_shadows.py").run({
        "@timestamp": _iso(now - timedelta(minutes=4)),
        "event": {"id": f"edr-{uuid.uuid4().hex[:10]}"},
        "host": {"name": host, "ip": f"192.168.10.{random.randint(20, 200)}"},
        "user": {"name": user},
        "process": {
            "name": "vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "parent": {"name": "powershell.exe"},
            "hash": {"sha256": "5f2b7c1d9a0e4b3c8d6f1a2e7b9c0d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c"},
        },
        "risk_score": 96,
    })
    # Same host beacons to known ransomware C2 two minutes later -> correlated into the same case.
    create_alert_with_context(
        case_defaults={"title": first.case.title, "correlation_uid": first.case.correlation_uid},
        alert_fields={
            "title": f"Outbound connection from {host} to known C2 91.240.118.172",
            "severity": Severity.HIGH,
            "confidence": Confidence.HIGH,
            "impact": Impact.HIGH,
            "disposition": Disposition.DETECTED,
            "action": AlertAction.OBSERVED,
            "status": AlertStatus.NEW,
            "rule_id": "NDR-07-Known-C2-Destination",
            "rule_name": "NDR Known C2 Destination",
            "correlation_uid": first.case.correlation_uid,
            "analytic_type": AlertAnalyticType.RULE,
            "product_category": ProductCategory.NDR,
            "product_name": "NDR",
            "product_vendor": "Network Sensor",
            "first_seen_time": now - timedelta(minutes=2),
            "last_seen_time": now - timedelta(minutes=2),
            "desc": f"{host} opened TLS sessions to 91.240.118.172:443 every 60s (beacon pattern).",
            "labels": ["c2", "beacon"],
            "tactic": "Command and Control",
            "technique": "T1071 - Application Layer Protocol",
            "raw_data": {"src_host": host, "dst_ip": "91.240.118.172", "dst_port": 443, "interval_s": 60},
        },
        artifacts=[
            {"value": host, "type": ArtifactType.HOSTNAME, "role": ArtifactRole.AFFECTED, "name": ArtifactName.AFFECTED_HOST},
            {"value": "91.240.118.172", "type": ArtifactType.IP_ADDRESS, "role": ArtifactRole.ACTOR, "name": ArtifactName.DESTINATION_IP},
        ],
        enrichments=[],
    )
    return first.case


def phishing():
    now = timezone.now()
    victim = random.choice(["neha.gupta", "arjun.rao", "kavya.menon"])
    result = _module("mail_user_report_phishing.py").run({
        "eventTime": _iso(now - timedelta(minutes=6)),
        "sender": "it-support@micros0ft-secure-login.com",
        "recipient": f"{victim}@corp.example",
        "reporter": f"{victim}@corp.example",
        "subject": "Action required: your mailbox password expires today",
        "message_id": f"<{uuid.uuid4().hex}@micros0ft-secure-login.com>",
        "urls": ["https://micros0ft-secure-login.com/reset"],
        "attachments": [{"filename": "Password_Reset_Form.html", "sha256": uuid.uuid4().hex + uuid.uuid4().hex}],
        "event.risk_score": 75,
    })
    return result.case


def cloud_privesc():
    now = timezone.now()
    actor = f"dev-ci-{_suffix()}"
    result = _module("aws_iam_privilege_escalation_attach_user_policy.py").run({
        "eventTime": _iso(now - timedelta(minutes=3)),
        "eventID": str(uuid.uuid4()),
        "eventName": "AttachUserPolicy",
        "awsRegion": "ap-south-1",
        "sourceIPAddress": "89.248.165.12",
        "userAgent": "aws-cli/2.15.0 Python/3.11",
        "userIdentity": {
            "type": "IAMUser",
            "userName": actor,
            "arn": f"arn:aws:iam::412345678901:user/{actor}",
            "accountId": "412345678901",
            "accessKeyId": f"AKIA{uuid.uuid4().hex[:16].upper()}",
        },
        "requestParameters": {"userName": actor, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        "event.outcome": "success",
        "log.level": "critical",
        "event.risk_score": 92,
    })
    return result.case


def vpn_bruteforce():
    now = timezone.now()
    user = random.choice(["svc_backup", "hr_admin", "finance_ops"])
    corr = f"demo-vpn-{uuid.uuid4().hex[:8]}"
    result = create_alert_with_context(
        case_defaults={
            "title": f"VPN brute force followed by successful login for {user}",
            "severity": Severity.HIGH,
            "impact": CaseImpact.HIGH,
            "priority": CasePriority.HIGH,
            "confidence": CaseConfidence.HIGH,
            "description": f"37 failed VPN logins for {user} from 45.95.11.22 within 4 minutes, then a successful login.",
            "category": ProductCategory.IAM,
            "tags": ["brute-force", "vpn", "credential-access"],
            "correlation_uid": corr,
        },
        alert_fields={
            "title": f"Successful VPN login for {user} after 37 failures from 45.95.11.22",
            "severity": Severity.HIGH,
            "confidence": Confidence.HIGH,
            "impact": Impact.HIGH,
            "disposition": Disposition.ALLOWED,
            "action": AlertAction.OBSERVED,
            "status": AlertStatus.NEW,
            "rule_id": "IAM-03-VPN-Brute-Force-Success",
            "rule_name": "VPN Brute Force Then Success",
            "correlation_uid": corr,
            "analytic_type": AlertAnalyticType.RULE,
            "product_category": ProductCategory.IAM,
            "product_name": "VPN Gateway",
            "product_vendor": "Network Access",
            "first_seen_time": now - timedelta(minutes=5),
            "last_seen_time": now - timedelta(minutes=1),
            "desc": "Password spraying pattern followed by a successful authentication from the same source.",
            "labels": ["brute-force", "credential-access"],
            "tactic": "Credential Access",
            "technique": "T1110 - Brute Force",
            "raw_data": {"user": user, "src_ip": "45.95.11.22", "failures": 37, "gateway": "vpn-gw-01"},
        },
        artifacts=[
            {"value": user, "type": ArtifactType.USER_NAME, "role": ArtifactRole.TARGET, "name": ArtifactName.TARGET_USER},
            {"value": "45.95.11.22", "type": ArtifactType.IP_ADDRESS, "role": ArtifactRole.ACTOR, "name": ArtifactName.SOURCE_IP},
            {"value": "vpn-gw-01", "type": ArtifactType.HOSTNAME, "role": ArtifactRole.AFFECTED, "name": ArtifactName.AFFECTED_HOST},
        ],
        enrichments=[],
    )
    return result.case


def ssh_bruteforce():
    """Medium-severity brute force from a known-bad IP that never got in: the agents block the IP on their own."""
    now = timezone.now()
    corr = f"demo-ssh-{uuid.uuid4().hex[:8]}"
    src = "89.248.165.12"
    attempts = random.randint(180, 420)
    result = create_alert_with_context(
        case_defaults={
            "title": f"SSH brute force from {src} against the public bastion",
            "severity": Severity.MEDIUM,
            "impact": CaseImpact.LOW,
            "priority": CasePriority.MEDIUM,
            "confidence": CaseConfidence.MEDIUM,
            "description": f"{attempts} failed SSH logins from {src} in 10 minutes. No successful login.",
            "category": ProductCategory.NDR,
            "tags": ["brute-force", "ssh", "internet-noise"],
            "correlation_uid": corr,
        },
        alert_fields={
            "title": f"{attempts} failed SSH logins from {src}",
            "severity": Severity.MEDIUM,
            "confidence": Confidence.MEDIUM,
            "impact": Impact.LOW,
            "disposition": Disposition.BLOCKED,
            "action": AlertAction.DENIED,
            "status": AlertStatus.NEW,
            "rule_id": "NET-07-SSH-Brute-Force",
            "rule_name": "SSH Brute Force (no success)",
            "correlation_uid": corr,
            "analytic_type": AlertAnalyticType.RULE,
            "product_category": ProductCategory.NDR,
            "product_name": "Perimeter Firewall",
            "product_vendor": "Network Security",
            "first_seen_time": now - timedelta(minutes=10),
            "last_seen_time": now - timedelta(minutes=1),
            "desc": "High-volume SSH authentication failures from a single external source; every attempt failed.",
            "labels": ["brute-force", "credential-access"],
            "tactic": "Credential Access",
            "technique": "T1110.001 - Password Guessing",
            "raw_data": {"src_ip": src, "dst_port": 22, "failures": attempts, "successes": 0},
        },
        artifacts=[
            {"value": src, "type": ArtifactType.IP_ADDRESS, "role": ArtifactRole.ACTOR, "name": ArtifactName.SOURCE_IP},
        ],
        enrichments=[],
    )
    return result.case


def authorized_scan():
    now = timezone.now()
    corr = f"demo-scan-{uuid.uuid4().hex[:8]}"
    result = create_alert_with_context(
        case_defaults={
            "title": "Port scan from internal host scan-nessus-01 (authorized pentest window)",
            "severity": Severity.MEDIUM,
            "impact": CaseImpact.LOW,
            "priority": CasePriority.LOW,
            "confidence": CaseConfidence.MEDIUM,
            "description": "Horizontal TCP scan of 254 hosts from 10.0.5.20 during the scheduled authorized vulnerability scan.",
            "category": ProductCategory.NDR,
            "tags": ["scan", "pentest"],
            "correlation_uid": corr,
        },
        alert_fields={
            "title": "Horizontal port scan from 10.0.5.20",
            "severity": Severity.MEDIUM,
            "confidence": Confidence.MEDIUM,
            "impact": Impact.LOW,
            "disposition": Disposition.DETECTED,
            "action": AlertAction.OBSERVED,
            "status": AlertStatus.NEW,
            "rule_id": "NDR-02-Horizontal-Scan",
            "rule_name": "NDR Horizontal Port Scan",
            "correlation_uid": corr,
            "analytic_type": AlertAnalyticType.RULE,
            "product_category": ProductCategory.NDR,
            "product_name": "NDR",
            "product_vendor": "Network Sensor",
            "first_seen_time": now - timedelta(minutes=8),
            "last_seen_time": now - timedelta(minutes=1),
            "desc": "Source matches the authorized scanner scan-nessus-01 used by the security team.",
            "labels": ["scan", "authorized"],
            "tactic": "Discovery",
            "technique": "T1046 - Network Service Discovery",
            "raw_data": {"src_ip": "10.0.5.20", "src_host": "scan-nessus-01", "targets": 254},
        },
        artifacts=[
            {"value": "scan-nessus-01", "type": ArtifactType.HOSTNAME, "role": ArtifactRole.ACTOR, "name": ArtifactName.SOURCE_HOST},
            {"value": "10.0.5.20", "type": ArtifactType.IP_ADDRESS, "role": ArtifactRole.ACTOR, "name": ArtifactName.SOURCE_IP},
        ],
        enrichments=[],
    )
    return result.case


def encoded_powershell():
    now = timezone.now()
    host = f"lap-fin-{_suffix()}"
    user = random.choice(["neha.gupta", "arjun.rao", "kavya.menon", "ishaan.bose"])
    corr = f"demo-ps-{uuid.uuid4().hex[:8]}"
    result = create_alert_with_context(
        case_defaults={
            "title": f"Encoded PowerShell launched from Outlook on {host}",
            "severity": Severity.MEDIUM,
            "impact": CaseImpact.MEDIUM,
            "priority": CasePriority.MEDIUM,
            "confidence": CaseConfidence.MEDIUM,
            "description": f"{user} opened an attachment and outlook.exe spawned powershell.exe -enc. No network IOC observed yet.",
            "category": ProductCategory.EDR,
            "tags": ["powershell", "execution"],
            "correlation_uid": corr,
        },
        alert_fields={
            "title": f"powershell.exe -EncodedCommand spawned by outlook.exe on {host}",
            "severity": Severity.MEDIUM,
            "confidence": Confidence.MEDIUM,
            "impact": Impact.MEDIUM,
            "disposition": Disposition.DETECTED,
            "action": AlertAction.OBSERVED,
            "status": AlertStatus.NEW,
            "rule_id": "EDR-05-Office-Spawns-Encoded-PowerShell",
            "rule_name": "Office Application Spawns Encoded PowerShell",
            "correlation_uid": corr,
            "analytic_type": AlertAnalyticType.RULE,
            "product_category": ProductCategory.EDR,
            "product_name": "EDR",
            "product_vendor": "Endpoint Security",
            "first_seen_time": now - timedelta(minutes=3),
            "last_seen_time": now - timedelta(minutes=3),
            "desc": "Parent outlook.exe; command line contains -EncodedCommand with a 1.2 KB base64 payload.",
            "labels": ["powershell", "execution"],
            "tactic": "Execution",
            "technique": "T1059.001 - PowerShell",
            "raw_data": {"host": host, "user": user, "parent": "outlook.exe", "cmd": "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA..."},
        },
        artifacts=[
            {"value": host, "type": ArtifactType.HOSTNAME, "role": ArtifactRole.AFFECTED, "name": ArtifactName.AFFECTED_HOST},
            {"value": user, "type": ArtifactType.USER_NAME, "role": ArtifactRole.ACTOR, "name": ArtifactName.SOURCE_USER},
            {"value": "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA...", "type": ArtifactType.COMMAND_LINE, "role": ArtifactRole.RELATED, "name": ArtifactName.PROCESS_COMMAND_LINE},
        ],
        enrichments=[],
    )
    return result.case


SCENARIOS = {
    "ransomware": {"label": "Ransomware precursor", "description": "Shadow-copy deletion on a production web server plus C2 beaconing.", "expect": "True Positive · Critical · auto-escalated", "fn": ransomware},
    "phishing": {"label": "Credential phishing", "description": "User reports a fake Microsoft password-reset email with a harvesting link.", "expect": "True Positive · sender blocked, email purged", "fn": phishing},
    "cloud_privesc": {"label": "AWS privilege escalation", "description": "CI user attaches AdministratorAccess to itself from a known-bad IP.", "expect": "True Positive · IAM revocation needs approval", "fn": cloud_privesc},
    "vpn_bruteforce": {"label": "VPN brute force", "description": "Password spraying from an external IP ends in a successful login.", "expect": "True Positive · session revoke + reset", "fn": vpn_bruteforce},
    "encoded_powershell": {"label": "Suspicious PowerShell", "description": "Outlook spawns encoded PowerShell on a finance laptop; no known-bad IOC.", "expect": "Suspicious · stays with Tier-1 to decide", "fn": encoded_powershell},
    "ssh_bruteforce": {"label": "SSH brute force (auto-blocked)", "description": "Hundreds of failed SSH logins from a known-bad IP; nothing got in.", "expect": "True Positive · Medium · IP blocked by the agents, no approval", "fn": ssh_bruteforce},
    "authorized_scan": {"label": "Authorized scan (false positive)", "description": "Internal Nessus scanner during the approved pentest window.", "expect": "False Positive · closed fast, no actions", "fn": authorized_scan},
}


def list_scenarios():
    return [{"key": k, **{f: v for f, v in s.items() if f != "fn"}} for k, s in SCENARIOS.items()]


def launch(key):
    if key not in SCENARIOS:
        raise KeyError(key)
    # One transaction: every correlated alert lands before the agent job becomes visible,
    # so the team runs once with the complete picture.
    with transaction.atomic():
        return SCENARIOS[key]["fn"]()
