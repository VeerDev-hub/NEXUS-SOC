# NEXUS-SOC: a multi-agent Security Operations Center

A Security Operations Center in which a **team of AI agents** investigates every alert
end to end, and **human analysts stay in control** through a role-based console.

- **7 cooperating agents.** A Supervisor routes each case through Triage, Threat Intel,
  Asset & Identity, Investigation, Response and Reporting specialists.
- **Human in the loop.** Agents only *propose* containment actions. Policy sets the risk
  tier, and Medium/High/Critical actions wait for a Tier-2 Responder or the SOC Manager.
- **5 roles:** SOC Admin, SOC Manager, Tier-1 Analyst, Tier-2 Incident Responder and
  Auditor. Each role has its own home page and permissions, enforced on every API endpoint.
- **Runs anywhere.** Use DeepSeek, OpenAI or Google Gemini, or the **built-in offline
  engine** with no internet or API key. In *Auto* mode it falls back to offline when the
  LLM is unreachable.
- **Fully auditable.** Every routing decision, tool call, model, token count and approval
  is stored and shown in the Decision Trail and the Audit Log.

---

## Architecture

```mermaid
flowchart LR
    subgraph Sources
        SIEM[SIEM / EDR / Email / Cloud events]
    end
    subgraph Backend["Django backend"]
        MOD[Detection modules] --> CASE[(Cases · Alerts · Artifacts)]
        CASE --> Q[Agent job queue]
        Q --> ORCH
        subgraph ORCH["Multi-agent orchestrator"]
            SUP{Supervisor}
            SUP --> TRI[Triage]
            SUP --> TI[Threat Intel]
            SUP --> AST[Asset & Identity]
            SUP --> INV[Investigation]
            SUP --> RSP[Response]
            SUP --> REP[Reporting]
        end
        TI -. tool .-> TIP[(Threat-intel feeds)]
        AST -. tool .-> CMDB[(CMDB)]
        INV -. tool .-> LOGS[(SIEM search)]
        TRI -. tool .-> KB[(Knowledge base)]
        RSP --> PROP[Action proposals] --> POL{Risk policy}
        POL -- low risk --> EXEC[Simulated connectors]
        POL -- needs approval --> APPR[Approvals]
        ORCH <--> LLM[LLM gateway: DeepSeek / OpenAI / Gemini / offline engine]
        ORCH --> WS((WebSocket events))
    end
    SIEM --> MOD
    subgraph UI["Next.js console (role based)"]
        T1[Tier-1 queue]
        T2[Responder desk]
        MGR[Manager overview]
        AUD[Audit]
        ADM[Admin]
    end
    WS --> UI
    APPR <--> T2
    APPR <--> MGR
```

### How one case flows

1. A raw event reaches a **detection module**, which creates or correlates a case, its alerts and artifacts.
2. The **Supervisor** reads the shared case state and picks the next specialist. The LLM
   chooses the route, and **guardrails** reject illegal moves (for example, a response before
   any investigation). When Triage is confident the case is a false positive, the team skips
   straight to the report.
3. Each **specialist** calls its tools (threat intel, CMDB, log search, knowledge base) and then
   reasons to a **typed output**: the LLM must fill a Pydantic schema, or the offline engine
   produces the same schema with rules.
4. The **Response Agent** proposes actions from a fixed catalogue. The **risk tier comes from
   policy, not the LLM**, and is raised one level for business-critical assets.
5. The **Reporting Agent** writes the verdict, an executive summary and a technical report.
   Confirmed High/Critical incidents are **auto-escalated** to the Tier-2 queue.
6. Every step streams live to the console over WebSocket.

## Roles

| Role | Home page | Highlights |
|---|---|---|
| Tier-1 Analyst | My Queue | AI-triaged queue, false positives filtered, escalate to Tier-2 |
| Tier-2 Incident Responder | Responder Desk | Escalated incidents, approve/reject Medium-High actions, resolve cases |
| SOC Manager | SOC Overview | KPIs (MTTR, AI/analyst agreement), workload, approve Critical actions |
| Auditor | Audit Log | Read-only: every change by people and agents, decision trail |
| SOC Admin | Admin Console | Users & roles, LLM providers, agent runtime mode |

Every home page opens with the same **SOC posture** charts: cases per day by severity
(14 days), open cases by severity, the case pipeline, a MITRE ATT&CK tactic × severity
heatmap, alerts by source and mean time to resolve.

## Quick start (Docker)

```bash
cp .env.example .env          # optionally add DEEPSEEK_API_KEY=...
docker compose up -d --build
```

Open **http://localhost:3000** and sign in as one of the demo personas
(password `SocDemo@2026`):

| Username | Persona | Role |
|---|---|---|
| `analyst` | Rohan Verma | Tier-1 Analyst |
| `responder` | Ananya Iyer | Tier-2 Incident Responder |
| `manager` | Priya Sharma | SOC Manager |
| `auditor` | Vikram Nair | Auditor |
| `admin` | Aarav Mehta | SOC Admin |

On first start the stack seeds **two weeks of realistic history**: about 50 cases processed by
the agent team and worked by analysts. Use **Launch attack scenario** to generate a live incident.

## Local development (Windows)

Requirements: Python 3.14 + [uv](https://docs.astral.sh/uv/), Node.js 24, Docker Desktop.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1          # start everything
powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1 -Seed    # rebuild demo history
```

| Service | URL |
|---|---|
| Console (Next.js) | http://localhost:3000 |
| API + WebSocket (Django/Channels) | http://localhost:8000 |
| API docs (OpenAPI) | http://localhost:8000/api/docs/ |

Useful commands (run from `backend/`):

```bash
python manage.py seed_demo --reset        # fresh 14-day demo history
python manage.py seed_demo_users          # (re)create the five demo accounts
python manage.py test                     # backend test suite
```

## LLM configuration

| Mode | Behaviour |
|---|---|
| **Auto** (default) | Use the configured LLM; fall back to the offline engine if it is unreachable or errors |
| **Online only** | Always use the LLM; errors stop the run (for model evaluation) |
| **Offline engine** | Never call an LLM: deterministic rule-based agents (air-gapped demos) |

Providers are added in **Admin → Platform settings**, or via environment variables
(`DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`). All providers use their
OpenAI-compatible endpoints. Individual agents can be pinned to a model with tags such as
`agent:investigation`.

## Repository layout

```
backend/
  apps/agentic/multiagent/   orchestrator, supervisor, agents, tools, LLM gateway, action policy
  apps/agentic/demo.py       attack scenarios for live demos
  apps/accounts/rbac.py      roles and permission matrix
  apps/dashboard/metrics.py  SOC KPIs and chart series
  data/agents/               system prompt per agent
  custom/modules/            detection modules (EDR, email, cloud)
frontend/                    Next.js 16 + Tailwind CSS 4 console
docs/research/               research paper material and evaluation code
scripts/start-dev.ps1        one-command local start (Windows)
docker-compose.yml           full stack
```

## Licence

Released under the [MIT Licence](LICENSE).
