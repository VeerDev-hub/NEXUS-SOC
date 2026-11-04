<#
.SYNOPSIS
  Start the NEXUS-SOC Windows live detector (elevates to Administrator automatically).

.DESCRIPTION
  1. Re-launches itself as Administrator (UAC prompt) - the Security log is admin-only.
  2. Turns on the Windows audit policies the detection rules rely on:
       User Account Management     4720 created, 4722 enabled, 4724 reset, 4726 deleted, 4740 lockout
       Security Group Management   4728/4732/4756 added to a privileged group
       Logon / Account Lockout     4624/4625 logons, brute force, RDP from the internet
       Process Creation            4688 + full command lines (encoded PowerShell, LOLBins, ...)
       Other Object Access Events  4698 scheduled task created
       Audit Policy Change         4719 audit policy changed
       Security System Extension   4697 service installed
  3. Checks that PostgreSQL and the agent worker are up.
  4. Runs `manage.py run_live_detection` (Security, System, PowerShell, Defender logs + syslog 5514).

.PARAMETER SkipAuditPolicy
  Do not change audit settings (use what the machine already has).

.PARAMETER ScriptBlockLogging
  Also enable PowerShell Script Block Logging (4104 for every script; more log volume).

.PARAMETER NoBaseline
  Run without behavioural baselines (UEBA).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\start-detector.ps1
#>
param(
    [switch]$SkipAuditPolicy,
    [switch]$ScriptBlockLogging,
    [switch]$NoBaseline
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$python = Join-Path $backend ".venv\Scripts\python.exe"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Ok($msg) { Write-Host "    [ok] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "    [!]  $msg" -ForegroundColor Yellow }

# ---- 1. Elevate ---------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator rights are needed to read the Windows Security log. Asking for elevation..." -ForegroundColor Yellow
    $forward = @()
    if ($SkipAuditPolicy) { $forward += "-SkipAuditPolicy" }
    if ($ScriptBlockLogging) { $forward += "-ScriptBlockLogging" }
    if ($NoBaseline) { $forward += "-NoBaseline" }
    $argList = @("-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"") + $forward
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argList | Out-Null
    } catch {
        Write-Host "Elevation was cancelled. Run this script from an Administrator PowerShell instead." -ForegroundColor Red
        exit 1
    }
    exit 0
}
$Host.UI.RawUI.WindowTitle = "NEXUS-SOC live detection (Administrator)"

if (-not (Test-Path $python)) {
    Write-Host "Backend virtualenv not found at $python. Run 'uv sync' in backend first." -ForegroundColor Red
    exit 1
}

# ---- 2. Audit policy ----------------------------------------------------------------
if (-not $SkipAuditPolicy) {
    Step "Enabling Windows audit policies used by the detection rules"
    # Subcategory GUIDs work on every Windows display language.
    $subcategories = [ordered]@{
        "User Account Management"     = "{0CCE9235-69AE-11D9-BED3-505054503030}"
        "Security Group Management"   = "{0CCE9237-69AE-11D9-BED3-505054503030}"
        "Logon"                       = "{0CCE9215-69AE-11D9-BED3-505054503030}"
        "Account Lockout"             = "{0CCE9217-69AE-11D9-BED3-505054503030}"
        "Process Creation"            = "{0CCE922B-69AE-11D9-BED3-505054503030}"
        "Other Object Access Events"  = "{0CCE9227-69AE-11D9-BED3-505054503030}"
        "Audit Policy Change"         = "{0CCE922F-69AE-11D9-BED3-505054503030}"
        "Security System Extension"   = "{0CCE9211-69AE-11D9-BED3-505054503030}"
    }
    foreach ($name in $subcategories.Keys) {
        & auditpol.exe /set /subcategory:$($subcategories[$name]) /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -eq 0) { Ok $name } else { Warn "Could not enable $name (auditpol exit $LASTEXITCODE)" }
    }

    # Include the full command line in 4688 process-creation events.
    $auditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    New-Item -Path $auditKey -Force | Out-Null
    Set-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
    Ok "Command lines in process-creation events (4688)"

    if ($ScriptBlockLogging) {
        $sbKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        New-Item -Path $sbKey -Force | Out-Null
        Set-ItemProperty -Path $sbKey -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
        Ok "PowerShell Script Block Logging (4104)"
    }
} else {
    Warn "Audit policy left unchanged (-SkipAuditPolicy)"
}

# ---- 3. Pre-flight checks ------------------------------------------------------------
Step "Checking the platform"
$dbPort = 5432
$dockerEnv = Join-Path $root "development\docker\.env"
if (Test-Path $dockerEnv) {
    $line = Select-String -Path $dockerEnv -Pattern "^POSTGRES_HOST_PORT=(\d+)" | Select-Object -First 1
    if ($line) { $dbPort = [int]$line.Matches[0].Groups[1].Value }
}
$checks = @(
    @{ Name = "PostgreSQL"; Port = $dbPort; Hint = "docker compose -f development\docker\compose.yaml up -d" },
    @{ Name = "API (8000)"; Port = 8000; Hint = "scripts\start-dev.ps1" },
    @{ Name = "Ollama (11434)"; Port = 11434; Hint = "start the Ollama app (local LLM fallback)" }
)
$dbUp = $true
foreach ($check in $checks) {
    $listening = Get-NetTCPConnection -LocalPort $check.Port -State Listen -ErrorAction SilentlyContinue
    if ($listening) { Ok $check.Name } else {
        Warn "$($check.Name) is not running - $($check.Hint)"
        if ($check.Name -eq "PostgreSQL") { $dbUp = $false }
    }
}
$workers = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match "run_agentic_case_analysis_worker" }
# A virtualenv python.exe is a launcher that starts the real interpreter: count each worker once.
$workerIds = @($workers | ForEach-Object { $_.ProcessId })
$workers = $workers | Where-Object { $workerIds -notcontains $_.ParentProcessId }
if ($workers) { Ok "Agent workers: $(@($workers).Count)" } else { Warn "No agent worker running - cases will be created but not analysed until one starts" }
if (-not $dbUp) {
    Write-Host "`nPostgreSQL is required. Start it and run this script again." -ForegroundColor Red
    exit 1
}

# ---- 4. Run ---------------------------------------------------------------------------
Step "Starting live detection (Ctrl+C to stop)"
Set-Location $backend
$detectorArgs = @("manage.py", "run_live_detection", "--windows", "on")
if ($NoBaseline) { $detectorArgs += "--no-baseline" }
& $python @detectorArgs
