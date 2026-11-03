# NEXUS-SOC: backend

Django + Django REST Framework + Channels backend for the multi-agent SOC.

## Development

Run from the `backend` directory (or use `scripts/start-dev.ps1` from the repository root):

```powershell
uv sync
copy .env.example .env
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py seed_demo --if-empty
.\.venv\Scripts\python.exe -m uvicorn soc.asgi:application --host 127.0.0.1 --port 8000
.\.venv\Scripts\python.exe manage.py run_agentic_case_analysis_worker --interval 1
```

## Key packages

| Path | Purpose |
|---|---|
| `apps/agentic/multiagent/` | Orchestrator, Supervisor, specialist agents, tools, LLM gateway, action policy |
| `apps/agentic/demo.py` | Attack scenarios for live demos |
| `apps/accounts/rbac.py` | Roles and permission matrix |
| `apps/dashboard/metrics.py` | SOC KPIs and chart series |
| `data/agents/` | System prompt for each agent |
| `custom/modules/` | Detection modules (EDR, email, cloud) |

## Commands

```powershell
.\.venv\Scripts\python.exe manage.py seed_demo --reset     # fresh 14-day demo history
.\.venv\Scripts\python.exe manage.py seed_demo_users       # five demo accounts
.\.venv\Scripts\python.exe manage.py test                  # test suite
```

API documentation is served by the backend at `/api/docs/` (Swagger UI) and `/api/redoc/`.
