# NEXUS-SOC - Frontend

Next.js 16 + Tailwind CSS 4 console for the multi-agent SOC. Every screen is driven by the
signed-in user's role and permissions (returned by `/api/auth/me/`).

## Run (development)

```bash
npm install
npm run dev            # http://localhost:3000
```

The dev server proxies `/api/*` to the Django backend (`BACKEND_URL`, default
`http://127.0.0.1:8000`). Live agent updates use the backend WebSocket
(`NEXT_PUBLIC_WS_URL`, see `.env.development`).

## Structure

| Path | Purpose |
|---|---|
| `src/app/login` | Sign-in with demo personas |
| `src/app/(app)/queue` | Tier-1 Analyst home |
| `src/app/(app)/responder` | Tier-2 Responder home (approvals) |
| `src/app/(app)/manager` | SOC Manager KPIs |
| `src/app/(app)/audit` | Auditor home / audit log |
| `src/app/(app)/admin` | Admin console, users & roles, LLM settings |
| `src/app/(app)/cases/[id]` | Case War Room: live agent graph, timeline, report, approvals |
| `src/components/agents` | Agent graph, timeline, report and approval components |
| `src/lib` | API client, auth store, realtime WebSocket, queries |
