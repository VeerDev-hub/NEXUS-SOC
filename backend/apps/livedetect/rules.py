"""Real-time detection rules for live logs.

A rule matches single events and can additionally require
  * a threshold: N matching events for the same key inside a time window, optionally
    counting distinct values of a field (e.g. distinct destination ports for a port scan);
  * a preceding rule: e.g. a successful login from an IP that just failed many times.

``match`` returns a dict of extracted fields (the event matched) or ``None``.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable

from apps.alerts.models import AlertTactic, ProductCategory, Severity

from .events import LogEvent

IP = r"(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})"


@dataclass(frozen=True)
class After:
    """Require that ``rule_id`` matched at least ``min_count`` times in the last ``window_seconds``."""

    rule_id: str
    min_count: int
    window_seconds: int


@dataclass(frozen=True)
class Rule:
    id: str
    title: str  # str.format template over extracted fields
    description: str
    severity: str
    tactic: str
    technique: str
    category: str
    match: Callable[[LogEvent], dict | None]
    group_by: tuple = ()
    threshold: int = 1
    window_seconds: int = 60
    distinct: str = ""
    after: After | None = None
    mitigation: str = ""
    tags: tuple = ()
    sources: tuple = ()  # restrict to "syslog"/"file"/"windows"; empty = any
    alert: bool = True  # False = helper rule that only records history for other rules
    extra: dict = field(default_factory=dict)

    def applies_to(self, event):
        return not self.sources or event.source in self.sources


# ---------------------------------------------------------------------------
# Matcher helpers
# ---------------------------------------------------------------------------

def regex(pattern, *, programs=(), flags=re.I, on="message"):
    compiled = re.compile(pattern, flags)
    programs = tuple(p.lower() for p in programs)

    def _match(event):
        if programs and not event.program.lower().startswith(programs):
            return None
        text = event.fields.get(on, "") if on != "message" else event.message
        found = compiled.search(str(text or ""))
        if not found:
            return None
        return {key: value for key, value in found.groupdict().items() if value}

    return _match


def windows_event(*event_ids, require=None, when=None):
    ids = set(event_ids)

    def _match(event):
        if event.source != "windows" or event.event_id not in ids:
            return None
        values = {k: v for k, v in event.fields.items() if k != "data" and isinstance(v, str) and v}
        if require and not all(values.get(k) for k in require):
            return None
        if when and not when(event, values):
            return None
        return values

    return _match


def http(predicate):
    def _match(event):
        if event.program != "http" or "url" not in event.fields:
            return None
        result = predicate(event.fields)
        if not result:
            return None
        values = {k: event.fields[k] for k in ("src_ip", "url", "user_agent", "method") if event.fields.get(k)}
        values["status"] = str(event.fields.get("status", ""))
        if isinstance(result, dict):
            values.update(result)
        return values

    return _match


# ---------------------------------------------------------------------------
# Linux / SSH / syslog rules
# ---------------------------------------------------------------------------

LINUX_RULES = [
    Rule(
        id="linux.ssh_bruteforce",
        title="SSH brute force from {src_ip} against {host}",
        description="Many failed SSH logins from one source in a short time.",
        severity=Severity.HIGH,
        tactic=AlertTactic.CREDENTIAL_ACCESS,
        technique="T1110.001 - Password Guessing",
        category=ProductCategory.SIEM,
        match=regex(rf"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from {IP}"),
        group_by=("host", "src_ip"),
        threshold=5,
        window_seconds=120,
        mitigation="Block the source IP, enforce key-based SSH authentication and fail2ban-style rate limiting.",
        tags=("ssh", "brute-force"),
    ),
    Rule(
        id="linux.ssh_login_after_bruteforce",
        title="Successful SSH login for {user} from brute-forcing IP {src_ip}",
        description="An SSH login succeeded from a source that was repeatedly failing to authenticate: likely compromised credentials.",
        severity=Severity.CRITICAL,
        tactic=AlertTactic.INITIAL_ACCESS,
        technique="T1078 - Valid Accounts",
        category=ProductCategory.SIEM,
        match=regex(rf"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from {IP}"),
        group_by=("host", "src_ip"),
        after=After("linux.ssh_bruteforce", min_count=3, window_seconds=900),
        mitigation="Disable the account, kill its sessions, rotate credentials and review commands run in the session.",
        tags=("ssh", "compromised-account"),
    ),
    Rule(
        id="linux.sudo_failures",
        title="Repeated sudo password failures by {actor_user} on {host}",
        description="A user repeatedly failed sudo authentication, possible privilege escalation attempt.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.PRIVILEGE_ESCALATION,
        technique="T1548.003 - Sudo and Sudo Caching",
        category=ProductCategory.SIEM,
        match=regex(r"pam_unix\(sudo:auth\): authentication failure;.*?\blogname=(?P<actor_user>\S+)"),
        group_by=("host", "actor_user"),
        threshold=3,
        window_seconds=300,
        tags=("sudo",),
    ),
    Rule(
        id="linux.user_created",
        title="New local account {target_user} created on {host}",
        description="A new local user account was created.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.PERSISTENCE,
        technique="T1136.001 - Local Account",
        category=ProductCategory.SIEM,
        match=regex(r"new user: name=(?P<target_user>[^,\s]+)", programs=("useradd", "adduser")),
        group_by=("host", "target_user"),
        tags=("account-created",),
    ),
    Rule(
        id="linux.privileged_group_add",
        title="{target_user} added to privileged group {group} on {host}",
        description="An account was added to an administrative group.",
        severity=Severity.HIGH,
        tactic=AlertTactic.PRIVILEGE_ESCALATION,
        technique="T1098 - Account Manipulation",
        category=ProductCategory.SIEM,
        match=regex(r"add '?(?P<target_user>[\w.-]+)'? to (?:shadow )?group '?(?P<group>sudo|wheel|admin|root|docker)'?"),
        group_by=("host", "target_user", "group"),
        tags=("privileged-group",),
    ),
    Rule(
        id="network.port_scan",
        title="Port scan from {src_ip}",
        description="One source touched many distinct destination ports in a short time (firewall logs).",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.DISCOVERY,
        technique="T1046 - Network Service Discovery",
        category=ProductCategory.NDR,
        match=regex(rf"\bSRC={IP}\b.*?\bDST=(?P<dst_ip>\S+).*?\bDPT=(?P<dst_port>\d+)"),
        group_by=("src_ip",),
        distinct="dst_port",
        threshold=15,
        window_seconds=60,
        mitigation="Block the scanning source at the perimeter and check what it reached.",
        tags=("port-scan",),
    ),
]


# ---------------------------------------------------------------------------
# Web access log rules
# ---------------------------------------------------------------------------

_SQLI = re.compile(r"(union(\s|\+|/\*.*?\*/)+select|'\s*or\s+'?\d+'?\s*=\s*'?\d|\bor\s+1\s*=\s*1\b|sleep\(\s*\d+\s*\)|benchmark\(|information_schema|;\s*drop\s+table|' ?--)", re.I)
_XSS = re.compile(r"(<script\b|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+=|alert\(|document\.cookie)", re.I)
_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|/proc/self/environ)", re.I)
_CMD_INJECTION = re.compile(r"(;|\||`|\$\()\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b|\$\{jndi:", re.I)
_SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|wpscan|nuclei|acunetix|nessus|openvas|hydra|wfuzz|ffuf)", re.I)


def _url_matches(pattern):
    return lambda fields: bool(pattern.search(fields.get("decoded_url", "")))


WEB_RULES = [
    Rule(
        id="web.sql_injection",
        title="SQL injection attempt from {src_ip}",
        description="HTTP request contains SQL injection payloads.",
        severity=Severity.HIGH,
        tactic=AlertTactic.INITIAL_ACCESS,
        technique="T1190 - Exploit Public-Facing Application",
        category=ProductCategory.WAF,
        match=http(_url_matches(_SQLI)),
        group_by=("src_ip",),
        mitigation="Block the source, confirm parameterised queries and review database logs for successful injection.",
        tags=("web", "sqli"),
    ),
    Rule(
        id="web.xss",
        title="Cross-site scripting attempt from {src_ip}",
        description="HTTP request contains script injection payloads.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.INITIAL_ACCESS,
        technique="T1190 - Exploit Public-Facing Application",
        category=ProductCategory.WAF,
        match=http(_url_matches(_XSS)),
        group_by=("src_ip",),
        tags=("web", "xss"),
    ),
    Rule(
        id="web.path_traversal",
        title="Path traversal / sensitive file access attempt from {src_ip}",
        description="HTTP request tries to read files outside the web root.",
        severity=Severity.HIGH,
        tactic=AlertTactic.INITIAL_ACCESS,
        technique="T1190 - Exploit Public-Facing Application",
        category=ProductCategory.WAF,
        match=http(_url_matches(_TRAVERSAL)),
        group_by=("src_ip",),
        tags=("web", "path-traversal"),
    ),
    Rule(
        id="web.command_injection",
        title="Command injection / Log4Shell attempt from {src_ip}",
        description="HTTP request contains OS command injection or JNDI lookup payloads.",
        severity=Severity.CRITICAL,
        tactic=AlertTactic.INITIAL_ACCESS,
        technique="T1190 - Exploit Public-Facing Application",
        category=ProductCategory.WAF,
        match=http(lambda f: bool(_CMD_INJECTION.search(f.get("decoded_url", "")) or "${jndi:" in f.get("user_agent", "").lower())),
        group_by=("src_ip",),
        tags=("web", "command-injection"),
    ),
    Rule(
        id="web.scanner_user_agent",
        title="Attack tool {scanner} probing from {src_ip}",
        description="HTTP requests carry the user agent of a known attack or scanning tool.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.RECONNAISSANCE,
        technique="T1595.002 - Vulnerability Scanning",
        category=ProductCategory.WAF,
        match=http(lambda f: (m := _SCANNER_UA.search(f.get("user_agent", ""))) and {"scanner": m.group(1).lower()}),
        group_by=("src_ip",),
        tags=("web", "attack-tool"),
    ),
    Rule(
        id="web.directory_bruteforce",
        title="Directory brute forcing from {src_ip} ({count} not-found responses)",
        description="One source produced a burst of 404 responses, typical of content discovery tools.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.RECONNAISSANCE,
        technique="T1595.003 - Wordlist Scanning",
        category=ProductCategory.WAF,
        match=http(lambda f: f.get("status") == 404),
        group_by=("src_ip",),
        threshold=20,
        window_seconds=60,
        tags=("web", "content-discovery"),
    ),
]


# ---------------------------------------------------------------------------
# Windows Event Log rules
# ---------------------------------------------------------------------------

_DEFENDER_EXCLUSION = re.compile(r"\\Windows Defender\\Exclusions\\(?:Paths|Extensions|Processes|IpAddresses)\\", re.I)
_SECURITY_SERVICES = {"windefend", "wdnissvc", "sense", "eventlog", "mpssvc", "wscsvc", "securityhealthservice"}


def _is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def _security_service_disabled(event, values):
    data = event.fields.get("data") or {}
    # 7040 params: 1 display name, 2 old start type, 3 new start type, 4 service key name.
    if data.get("param4", "").lower() not in _SECURITY_SERVICES or data.get("param3", "").lower() != "disabled":
        return False
    values["service"] = data.get("param1") or data.get("param4")
    return True


_ADMIN_GROUP = re.compile(r"admin|domain admins|enterprise admins|schema admins|remote desktop users|backup operators", re.I)


def _windows_logon_key(event, values):
    values.setdefault("src_ip", values.get("workstation") or "unknown")
    values.setdefault("user", values.get("target_user", ""))
    return True


WINDOWS_RULES = [
    Rule(
        id="windows.failed_logon_bruteforce",
        title="Windows logon brute force from {src_ip} against {host}",
        description="Many failed Windows logons (4625) from one source in a short time.",
        severity=Severity.HIGH,
        tactic=AlertTactic.CREDENTIAL_ACCESS,
        technique="T1110 - Brute Force",
        category=ProductCategory.EDR,
        match=windows_event(4625, when=_windows_logon_key),
        group_by=("host", "src_ip"),
        threshold=5,
        window_seconds=120,
        mitigation="Block the source, enable account lockout and require MFA for remote logons.",
        tags=("windows", "brute-force"),
    ),
    Rule(
        id="windows.logon_after_bruteforce",
        title="Successful Windows logon for {user} from brute-forcing source {src_ip}",
        description="A network/RDP logon (4624) succeeded from a source that was repeatedly failing.",
        severity=Severity.CRITICAL,
        tactic=AlertTactic.INITIAL_ACCESS,
        technique="T1078 - Valid Accounts",
        category=ProductCategory.EDR,
        match=windows_event(4624, when=lambda e, v: v.get("logon_type") in ("3", "8", "10") and _windows_logon_key(e, v)),
        group_by=("host", "src_ip"),
        after=After("windows.failed_logon_bruteforce", min_count=3, window_seconds=900),
        mitigation="Disable the account, end its sessions and rotate its password.",
        tags=("windows", "compromised-account"),
    ),
    Rule(
        id="windows.user_created",
        title="New Windows account {target_user} created on {host}",
        description="A user account was created (4720).",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.PERSISTENCE,
        technique="T1136.001 - Local Account",
        category=ProductCategory.EDR,
        match=windows_event(4720),
        group_by=("host", "target_user"),
        tags=("windows", "account-created"),
    ),
    Rule(
        id="windows.admin_group_add",
        title="Account {member} added to privileged group {target_user} on {host}",
        description="A member was added to an administrative security group (4728/4732/4756).",
        severity=Severity.HIGH,
        tactic=AlertTactic.PRIVILEGE_ESCALATION,
        technique="T1098 - Account Manipulation",
        category=ProductCategory.EDR,
        match=windows_event(4728, 4732, 4756, when=lambda e, v: bool(_ADMIN_GROUP.search(v.get("target_user", "")))),
        group_by=("host", "target_user", "member"),
        tags=("windows", "privileged-group"),
    ),
    Rule(
        id="windows.audit_log_cleared",
        title="Windows event log cleared on {host}",
        description="The Security (1102) or System (104) event log was cleared, a common anti-forensics step.",
        severity=Severity.CRITICAL,
        tactic=AlertTactic.DEFENSE_EVASION,
        technique="T1070.001 - Clear Windows Event Logs",
        category=ProductCategory.EDR,
        match=windows_event(1102, 104, when=lambda e, v: e.event_id == 1102 or "eventlog" in e.program.lower()),
        group_by=("host",),
        mitigation="Treat the host as compromised: isolate it and collect remaining forensic artefacts.",
        tags=("windows", "anti-forensics"),
    ),
    Rule(
        id="windows.service_installed",
        title="New service {service} installed on {host}",
        description="A new Windows service was installed (7045).",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.PERSISTENCE,
        technique="T1543.003 - Windows Service",
        category=ProductCategory.EDR,
        match=windows_event(7045),
        group_by=("host", "service"),
        tags=("windows", "service"),
    ),
    Rule(
        id="windows.scheduled_task_created",
        title="Scheduled task {task} created on {host}",
        description="A scheduled task was created (4698).",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.PERSISTENCE,
        technique="T1053.005 - Scheduled Task",
        category=ProductCategory.EDR,
        match=windows_event(4698),
        group_by=("host", "task"),
        tags=("windows", "scheduled-task"),
    ),
    Rule(
        id="windows.defender_malware",
        title="Microsoft Defender detected {threat} on {host}",
        description="Microsoft Defender reported malware (1116/1117).",
        severity=Severity.HIGH,
        tactic=AlertTactic.EXECUTION,
        technique="T1204 - User Execution",
        category=ProductCategory.EDR,
        match=windows_event(1116, 1117, when=lambda e, v: v.setdefault("threat", "malware") is not None),
        group_by=("host", "threat"),
        tags=("windows", "malware"),
    ),
    # ---- account manipulation (Security log, "User Account Management" auditing) ----
    Rule(
        id="windows.account_enabled",
        title="Windows account {target_user} enabled on {host}",
        description="A disabled account was re-enabled (4722). Attackers revive dormant accounts to avoid creating new ones.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.PERSISTENCE,
        technique="T1098 - Account Manipulation",
        category=ProductCategory.EDR,
        match=windows_event(4722),
        group_by=("host", "target_user"),
        tags=("windows", "account-manipulation"),
    ),
    Rule(
        id="windows.password_reset_by_other",
        title="Password of {target_user} reset by {actor_user} on {host}",
        description="One account reset another account's password (4724), a way to take over an account.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.PERSISTENCE,
        technique="T1098 - Account Manipulation",
        category=ProductCategory.EDR,
        match=windows_event(4724, when=lambda e, v: v.get("actor_user", "").lower() != v.get("target_user", "").lower()),
        group_by=("host", "target_user"),
        tags=("windows", "account-manipulation"),
    ),
    Rule(
        id="windows.account_lockout",
        title="Account {target_user} locked out on {host}",
        description="Too many bad passwords locked an account (4740): password guessing or spraying.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.CREDENTIAL_ACCESS,
        technique="T1110 - Brute Force",
        category=ProductCategory.EDR,
        match=windows_event(4740),
        group_by=("host", "target_user"),
        tags=("windows", "brute-force"),
    ),
    Rule(
        id="windows.user_deleted",
        title="Windows account {target_user} deleted on {host}",
        description="A local or domain account was deleted (4726): clean-up after an intrusion or sabotage.",
        severity=Severity.LOW,
        tactic=AlertTactic.IMPACT,
        technique="T1531 - Account Access Removal",
        category=ProductCategory.EDR,
        match=windows_event(4726),
        group_by=("host", "target_user"),
        tags=("windows", "account-deleted"),
    ),
    Rule(
        id="windows.rdp_logon_external",
        title="RDP logon for {target_user} from public IP {src_ip} on {host}",
        description="A Remote Desktop logon (4624, type 10) came from a public internet address.",
        severity=Severity.MEDIUM,
        tactic=AlertTactic.LATERAL_MOVEMENT,
        technique="T1021.001 - Remote Desktop Protocol",
        category=ProductCategory.EDR,
        match=windows_event(4624, when=lambda e, v: v.get("logon_type") == "10" and _is_public_ip(v.get("src_ip", ""))),
        group_by=("host", "src_ip", "target_user"),
        tags=("windows", "rdp"),
    ),
    # ---- defence evasion ----------------------------------------------------------
    Rule(
        id="windows.audit_policy_changed",
        title="Audit policy changed on {host} by {actor_user}",
        description="The system audit policy was changed (4719). Attackers turn auditing off to hide their tracks.",
        severity=Severity.HIGH,
        tactic=AlertTactic.DEFENSE_EVASION,
        technique="T1562.002 - Disable Windows Event Logging",
        category=ProductCategory.EDR,
        match=windows_event(4719),
        group_by=("host",),
        tags=("windows", "defense-evasion"),
    ),
    Rule(
        id="windows.defender_realtime_disabled",
        title="Microsoft Defender real-time protection disabled on {host}",
        description="Defender reported that real-time protection was turned off (5001).",
        severity=Severity.HIGH,
        tactic=AlertTactic.DEFENSE_EVASION,
        technique="T1562.001 - Disable or Modify Tools",
        category=ProductCategory.EDR,
        match=windows_event(5001),
        group_by=("host",),
        tags=("windows", "defender", "defense-evasion"),
    ),
    Rule(
        id="windows.defender_exclusion_added",
        title="Microsoft Defender exclusion added on {host}",
        description="A path, extension, process or IP was excluded from Defender scanning (5007). Malware adds exclusions so it is never scanned.",
        severity=Severity.HIGH,
        tactic=AlertTactic.DEFENSE_EVASION,
        technique="T1562.001 - Disable or Modify Tools",
        category=ProductCategory.EDR,
        match=windows_event(5007, when=lambda e, v: bool(_DEFENDER_EXCLUSION.search(v.get("new_value", "")))),
        group_by=("host", "new_value"),
        tags=("windows", "defender", "defense-evasion"),
    ),
    Rule(
        id="windows.defender_tamper_blocked",
        title="Tampering with Microsoft Defender blocked on {host}",
        description="Tamper Protection blocked an attempt to change Defender settings (5013).",
        severity=Severity.HIGH,
        tactic=AlertTactic.DEFENSE_EVASION,
        technique="T1562.001 - Disable or Modify Tools",
        category=ProductCategory.EDR,
        match=windows_event(5013),
        group_by=("host",),
        tags=("windows", "defender", "defense-evasion"),
    ),
    Rule(
        id="windows.security_service_disabled",
        title="Security service {service} set to disabled on {host}",
        description="The start type of a security service (Defender, Event Log, Firewall, Security Center) was changed to disabled (7040).",
        severity=Severity.HIGH,
        tactic=AlertTactic.DEFENSE_EVASION,
        technique="T1562.001 - Disable or Modify Tools",
        category=ProductCategory.EDR,
        match=windows_event(7040, when=_security_service_disabled),
        group_by=("host", "service"),
        tags=("windows", "defense-evasion"),
    ),
    # PowerShell's own "suspicious" 4104 warnings were evaluated on a real workstation and
    # dropped: 100% of 28 hits in 7 weeks were benign tooling (VS Code, cdxml modules,
    # vendor updaters). The command rules below inspect 4104 script text instead.
]


# ---------------------------------------------------------------------------
# Suspicious commands, any source (shell history, auditd, 4688, PowerShell 4104, 7045 ...)
# ---------------------------------------------------------------------------

_COMMAND_PATTERNS = [
    ("reverse_shell", "Reverse shell command", r"(/dev/tcp/\d|bash\s+-i\s+>&|nc(?:at)?(?:\.exe)?\s+.*-e\s+\S*(?:sh|cmd)|socket\.socket\(.*connect|mkfifo\s+/tmp/)", Severity.CRITICAL, AlertTactic.EXECUTION, "T1059.004 - Unix Shell"),
    ("download_exec", "Download-and-execute command", r"(curl|wget)\s+[^|;]*\|\s*(ba|z)?sh\b|IEX\s*\(?\s*\(?New-Object\s+Net\.WebClient|DownloadString\(|Invoke-WebRequest[^|]*\|\s*iex", Severity.HIGH, AlertTactic.EXECUTION, "T1105 - Ingress Tool Transfer"),
    ("encoded_powershell", "Encoded PowerShell command", r"powershell(?:\.exe)?[^\n]*\s-(?:e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", Severity.HIGH, AlertTactic.EXECUTION, "T1059.001 - PowerShell"),
    ("shadow_copy_delete", "Shadow copy deletion (ransomware precursor)", r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|bcdedit[^\n]*recoveryenabled\s+no|wbadmin\s+delete\s+catalog", Severity.CRITICAL, AlertTactic.IMPACT, "T1490 - Inhibit System Recovery"),
    ("credential_dumping", "Credential dumping tool", r"mimikatz|sekurlsa::|lsadump::|procdump[^\n]*lsass|comsvcs\.dll[^\n]*MiniDump|reg(?:\.exe)?\s+save\s+hklm\\sam", Severity.CRITICAL, AlertTactic.CREDENTIAL_ACCESS, "T1003 - OS Credential Dumping"),
    ("lolbin_download", "LOLBin used to download payload", r"certutil(?:\.exe)?[^\n]*-urlcache[^\n]*-f|bitsadmin(?:\.exe)?\s+/transfer|mshta(?:\.exe)?\s+https?://|regsvr32[^\n]*/i:https?://", Severity.HIGH, AlertTactic.DEFENSE_EVASION, "T1218 - System Binary Proxy Execution"),
    ("log_tampering", "Log or history tampering", r"rm\s+-rf?\s+/var/log|history\s+-c|unset\s+HISTFILE|wevtutil(?:\.exe)?\s+cl\s|Clear-EventLog|shred\s+[^\n]*\.log", Severity.HIGH, AlertTactic.DEFENSE_EVASION, "T1070 - Indicator Removal"),
    ("defender_disabled", "Security tooling disabled", r"Set-MpPreference[^\n]*-Disable\w+\s+\$?true|systemctl\s+(stop|disable)\s+(auditd|falcon|wazuh|osquery)|setenforce\s+0", Severity.HIGH, AlertTactic.DEFENSE_EVASION, "T1562.001 - Disable or Modify Tools"),
]


def _command_rule(key, label, pattern, severity, tactic, technique):
    compiled = re.compile(pattern, re.I)

    def _match(event):
        text = event.fields.get("command") or event.message
        found = compiled.search(str(text))
        if not found:
            return None
        command = str(text)
        start = max(0, found.start() - 120)
        return {"command": command[start:found.end() + 200].strip()}

    return Rule(
        id=f"command.{key}",
        title=f"{label} on {{host}}",
        description=f"{label} observed in live logs.",
        severity=severity,
        tactic=tactic,
        technique=technique,
        category=ProductCategory.EDR,
        match=_match,
        group_by=("host",),
        tags=("command", key.replace("_", "-")),
    )


COMMAND_RULES = [_command_rule(*spec) for spec in _COMMAND_PATTERNS]

RULES = LINUX_RULES + WEB_RULES + WINDOWS_RULES + COMMAND_RULES
RULES_BY_ID = {rule.id: rule for rule in RULES}
