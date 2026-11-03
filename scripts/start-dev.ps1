<#
.SYNOPSIS
  Start the NEXUS-SOC for local development / live demo on Windows.

.DESCRIPTION
  1. Starts PostgreSQL + Redis in Docker (development/docker/compose.yaml)
  2. Applies migrations and makes sure demo users exist
  3. Opens three terminal windows: API (uvicorn), agent worker, Next.js frontend

.PARAMETER Seed
  Rebuild the two-week demo history (wipes existing cases).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1
  powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1 -Seed
#>
param([switch]$Seed)

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

Step "Launching API, agent worker and frontend in new windows"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$backend'; `$Host.UI.RawUI.WindowTitle='SOC API'; & '$python' -m uvicorn soc.asgi:application --host 127.0.0.1 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$backend'; `$Host.UI.RawUI.WindowTitle='SOC agent worker'; & '$python' manage.py run_agentic_case_analysis_worker --interval 1"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$frontend'; `$Host.UI.RawUI.WindowTitle='SOC frontend'; npm run dev"

Write-Host "`nNEXUS-SOC is starting:" -ForegroundColor Green
Write-Host "  Console : http://localhost:3000"
Write-Host "  API docs: http://localhost:8000/api/docs/"
Write-Host "  Logins  : analyst / responder / manager / auditor / admin   (password SocDemo@2026)"
Write-Host "Close the three windows to stop. Docker services keep running (docker compose -f development\docker\compose.yaml stop)."
