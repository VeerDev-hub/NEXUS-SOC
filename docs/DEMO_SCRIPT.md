# Final review demo script (about 12 minutes)

## Before the panel arrives

1. Start the stack: `scripts\start-dev.ps1` (or `docker compose up -d`).
2. Optional fresh history: `scripts\start-dev.ps1 -Seed`.
3. Open http://localhost:3000 in two browser windows side by side:
   - Window A: **responder** (Rudra, Tier-2)
   - Window B: **manager** (Manish Bhargav, SOC Manager)
4. Check the header pill: `Offline engine` or `DeepSeek · deepseek-chat`. Both work. If the Wi-Fi
   is unreliable, set **Admin → Platform settings → Offline engine** before you start.

## 1. The problem (1 min)

SOC teams drown in alerts. Most are noise, and real incidents need many manual lookups
(threat intel, asset owner, logs) before anyone can act. Our answer: a team of AI agents does
that work in seconds, and humans keep the authority to act.

## 2. Role-based console (2 min)

Sign out and use the persona buttons on the login page.

- **Tier-1 (analyst):** *My Queue*. Point to the **AI flagged as false positive** tile and the
  **Suspicious** PowerShell cases: the AI is unsure, so a human decides.
- **Manager:** *SOC Overview*. Show **cases per day by severity**, the **ATT&CK heatmap**,
  **MTTR**, and **AI/analyst agreement** (the human verdict matches the AI in about 90% of cases).
- **Auditor:** read-only, with no action buttons anywhere. The audit log shows the *system/agents* actor.
- **Admin:** LLM provider settings, with three modes: Auto, Online and Offline.

## 3. Live incident (4 min): the core of the demo

In Window A (responder), click **Launch attack scenario → Ransomware precursor**.

Narrate the War Room as it fills in, about one agent per second:

1. **Supervisor → Triage:** "Every case starts with triage." Classified as a ransomware precursor.
2. **Threat Intel:** the C2 IP `91.240.118.172` is **malicious**. Open *tool calls* to show the real lookups.
3. **Asset & Identity:** `prod-web-xx` is **Critical** (e-commerce production).
4. **Investigation:** maps MITRE techniques (PowerShell T1059.001, Inhibit System Recovery T1490, C2 T1071 and more), with the timeline built from both alerts.
5. **Response:** about six actions. Low-risk ones (ticket, file quarantine) were **auto-executed by policy**.
6. **Reporting:** executive summary. The case is **auto-escalated** to Tier-2.

Key points:
- Click a node in the **agent graph** to jump to that step.
- The Supervisor's *reason* is recorded for every routing decision (explainability).
- Host isolation is **Critical** because the asset is business-critical. The Responder
  **cannot** approve it; it waits for the Manager.

## 4. Human in the loop (2 min)

- Window A (responder): approve **Force password reset**, then show the execution result with its reference ID.
- Window B (manager): the **Critical action** appears under *Critical actions needing a manager*.
  Approve **Network-isolate host**.
- Open the **Approvals center**: each action shows who approved it and when.

## 5. False-positive handling (1 min)

Launch **Authorized scan (false positive)**. The triage step finds the knowledge-base whitelist
entry for `scan-nessus-01`, the Supervisor **skips investigation and response**, and the case closes
in under a second with **no actions**. Point at the greyed-out agents in the graph.

## 6. Trust and governance (1 min)

- **Decision Trail** (auditor): every run, its trigger, LLM mode, confidence, duration and tokens.
- **Incident report → Export PDF.**
- Resilience: in Auto mode, if the LLM provider is down the run continues on the offline engine,
  and the step is labelled `offline` with the reason.

## 7. Wrap-up (1 min)

| Metric | Where to show it |
|---|---|
| AI triage time ~1 s offline / ~20-40 s with an LLM | Manager tiles |
| Noise filtered automatically | Tier-1 tile |
| Agreement with analysts | Manager tile |
| Human approval on every disruptive action | Approvals center |

## Likely questions

- **What if the LLM hallucinates an action?** It can only pick from a fixed catalogue; the target
  must be an artifact of the case; risk and approver are set by policy, and execution is
  simulated in this environment.
- **What if the LLM picks a nonsensical route?** The guardrail overrides it and logs
  "Guardrail override" in the timeline.
- **Why multiple agents instead of one big prompt?** Each agent gets a focused prompt, its own
  tools and a typed output. Steps are auditable, each agent can be pinned to a different model
  (cheap model for triage, stronger model for investigation) and failures are isolated.
- **Can it run without the internet?** Yes: the offline engine plus the local threat feed and mock CMDB.
