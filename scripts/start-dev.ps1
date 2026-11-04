<#
.SYNOPSIS
  Start the NEXUS-SOC for local development / live demo on Windows.

.DESCRIPTION
  1. Starts PostgreSQL + Redis in Docker (development/docker/compose.yaml)
  2. Applies migrations and makes sure demo users exist
  3. Warms up the local LLM (creates the 16k-context Ollama model if missing)
  4. Opens windows for the API, the agent workers, the Next.js frontend and the
     live detector (start-detector.ps1, elevated to Administrator)

.PARAMETER Seed
  Rebuild the two-week demo history (wipes existing cases).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1
  powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1 -Seed
#>
param(
    [switch]$Seed,
    [int]$Workers = 2,
    [int]$FrontendPort = 3001,
    [string]$OllamaModel = "qwen2.5-soc:7b-16k"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$python = Join-Path $backend ".venv\Scripts\python.exe"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

if (-not (Test-Path $python)) {
    Step "Creating backend virtualenv (uv sync)"
    Push-Location $backend; uv sync; Pop-Location
}
if (-not (Test-Path (Join-Path $backend ".env"))) {
    Step "Creating backend\.env from .env.example"
    Copy-Item (Join-Path $backend ".env.example") (Join-Path $backend ".env")
}
if (-not (Test-Path (Join-Path $frontend "node_modules"))) {
    Step "Installing frontend packages"
    Push-Location $frontend; npm install; Pop-Location
}

Step "Starting PostgreSQL and Redis (Docker)"
docker compose -f (Join-Path $root "development\docker\compose.yaml") up -d postgres redis-stack
Start-Sleep -Seconds 3

Step "Applying database migrations"
Push-Location $backend
& $python manage.py migrate --noinput
if ($Seed) {
    Step "Seeding two weeks of demo history (about a minute)"
    & $python manage.py seed_demo --reset
} else {
    & $python manage.py seed_demo --if-empty
}
Pop-Location

Step "Warming up the local LLM (Ollama) so the first case is not slow"
if (Get-Command ollama -ErrorAction SilentlyContinue) {
    $models = (& ollama list) -join "`n"
    if ($models -notmatch [regex]::Escape($OllamaModel) -and $OllamaModel -eq "qwen2.5-soc:7b-16k" -and $models -match "qwen2\.5:7b") {
        # Ollama's default 4k context truncates the agents' prompts; this variant uses 16k.
        $modelfile = Join-Path $env:TEMP "nexus-soc.Modelfile"
        "FROM qwen2.5:7b`nPARAMETER num_ctx 16384`nPARAMETER temperature 0" | Set-Content -Path $modelfile -Encoding ascii
        & ollama create $OllamaModel -f $modelfile | Out-Null
        Write-Host "    Created $OllamaModel (16k context)" -ForegroundColor Green
    }
}
try {
    $body = @{ model = $OllamaModel; prompt = "ok"; stream = $false; keep_alive = "3h" } | ConvertTo-Json
    Invoke-RestMethod -Uri "http://localhost:11434/api/generate" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 180 | Out-Null
    Write-Host "    $OllamaModel loaded and kept in GPU memory for 3 hours" -ForegroundColor Green
} catch {
    Write-Host "    Ollama not reachable ($($_.Exception.Message)); agents will use the cloud provider or the offline engine." -ForegroundColor Yellow
}

Step "Launching API, $Workers agent workers and frontend in new windows"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$backend'; `$Host.UI.RawUI.WindowTitle='SOC API'; & '$python' -m uvicorn soc.asgi:application --host 127.0.0.1 --port 8000"
foreach ($n in 1..$Workers) {
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$backend'; `$Host.UI.RawUI.WindowTitle='SOC agent worker $n'; & '$python' manage.py run_agentic_case_analysis_worker --interval 1"
}
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$frontend'; `$Host.UI.RawUI.WindowTitle='SOC frontend'; npm run dev -- -p $FrontendPort"
# The detector needs Administrator rights for the Security log; its script asks for elevation (UAC).
Start-Process powershell -ArgumentList "-ExecutionPolicy", "Bypass", "-File", "`"$(Join-Path $PSScriptRoot 'start-detector.ps1')`""

Write-Host "`nNEXUS-SOC is starting:" -ForegroundColor Green
Write-Host "  Console : http://localhost:$FrontendPort"
Write-Host "  API docs: http://localhost:8000/api/docs/"
Write-Host "  Syslog  : UDP/TCP port 5514 (live detection)"
Write-Host "  Logins  : analyst / responder / manager / auditor / admin   (password SocDemo@2026)"
Write-Host "Close the windows to stop. Docker services keep running (docker compose -f development\docker\compose.yaml stop)."
