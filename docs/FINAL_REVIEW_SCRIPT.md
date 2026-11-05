# NEXUS-SOC final review: presenter script

Read this aloud while showing the steps, or play the recorded video. Each chapter lists what to show, then what to say.

## 1. Introduction

- Welcome to NEXUS-SOC, a multi-agent security operations center, built for our final review.  
  *On screen: `card_title`*
- Security teams receive thousands of alerts every day. Most of them are noise, and every real incident needs many manual lookups before anyone can act.
- NEXUS-SOC hands that work to a team of seven AI agents, while people with the right role keep the authority to act.

## 2. How it works

- Here is the flow, from start to end.  
  *On screen: `card_arch`*
- Logs arrive from the SIEM, syslog, the Windows event log and cloud sources. Detection modules turn suspicious events into alerts, and related alerts are grouped into a case.
- A Supervisor agent then routes each case through six specialists: triage, threat intelligence, asset and identity context, investigation, response planning, and reporting.
- Low-risk containment runs automatically. Anything disruptive waits for a human approver, and high or critical incidents are emailed to the team.

## 3. Five roles

- Everything in the console depends on your role, and there are five of them.  
  *On screen: `goto_login`*
- A Tier-1 analyst works the alert queue. A Tier-2 responder handles escalations and approves containment actions.  
  *On screen: `hover_personas_1`*
- The SOC manager watches the whole team, assigns work, and approves critical actions. The auditor has read-only access to every decision. And the SOC admin manages users, integrations and the AI models.  
  *On screen: `hover_personas_2`*

## 4. Tier-1 analyst

- Let's start as Anchal, the Tier-1 analyst.  
  *On screen: `login_analyst`*
- Her queue has already been triaged by the AI team. Each case shows the AI verdict and severity, so she starts with what matters most.  
  *On screen: `scroll_queue`*
- Now let's simulate a real attack. The scenario generator sends raw security events through the same detection pipeline that a live SIEM feed uses.  
  *On screen: `open_launcher`*
- We'll launch a ransomware precursor: shadow copies deleted on a production web server, plus command-and-control beaconing.  
  *On screen: `launch_ransomware`*

## 5. Agents at work

- This is the case war room. The agent team picks the case up within a second, and every step streams in live.  
  *On screen: `wait_run_started`*
- The Supervisor sends it to Triage first, which classifies it as a ransomware precursor.  
  *On screen: `focus:Triage Agent`*
- Threat Intel checks every indicator. The command-and-control IP address is known to be malicious.  
  *On screen: `focus:Threat Intel Agent`*
- Asset Context finds that the server is a business-critical production system, and Investigation maps the activity to MITRE ATT&CK techniques and builds a timeline.  
  *On screen: `focus:Investigation Agent`*
- The Response agent proposes containment from a fixed catalogue of actions, and Reporting writes the incident report.  
  *On screen: `focus:Response Agent`*
- For this recording the agents run on the built-in offline engine, so every step is fast and repeatable. In live mode, the same agents call the configured language models.  
  *On screen: `make_emails`*
- Look at the actions. Low-risk ones, like opening a ticket and quarantining the file hash, already ran by policy. Isolating a critical server is critical risk, so it waits for the SOC manager.  
  *On screen: `scroll_actions`*
- Because the verdict is a confirmed true positive with critical severity, the case was escalated to Tier-2 automatically, and an alert email went out to the team.  
  *On screen: `scroll_top`*
- The incident report holds the executive summary, the affected assets, the indicators of compromise and the recommended actions, ready to export as a PDF.  
  *On screen: `report_tab`*

## 6. Alert email

- This is the alert email the team receives. Only high and critical cases trigger it, so nobody is flooded with mail.  
  *On screen: `show_alert_email`*
- It goes to the addresses in the configuration plus every teammate who switched alert emails on, with a button that opens the case directly.  
  *On screen: `scroll_email`*

## 7. Tier-2 responder

- Now we sign in as Rudra, the Tier-2 responder.  
  *On screen: `login_responder`*
- His home page shows escalated incidents and the containment actions waiting for his approval.  
  *On screen: `scroll_approvals`*
- He opens the new ransomware case from his queue and approves the forced password reset. The action runs, and the result is recorded with who approved it and when.  
  *On screen: `approve_reset`*
- He cannot approve the host isolation. That needs the SOC manager, so it stays locked for him.  
  *On screen: `show_locked`*

## 8. SOC manager

- Next, Manish, the SOC manager.  
  *On screen: `login_manager`*
- His overview shows the live state of the human and AI team: open cases, AI triage time, mean time to resolve, and how often analysts agree with the AI.
- The Assign work panel lists every open case, with unassigned and most severe cases first.  
  *On screen: `scroll_assign`*
- He assigns the ransomware case to Rudra from the dropdown. Rudra immediately gets an inbox message and an email with the case summary and a link.  
  *On screen: `assign_case`*
- This is that assignment email.  
  *On screen: `show_assign_email`*
- He opens the case, where the critical host isolation is waiting for him. He approves it, and the server is isolated.  
  *On screen: `approve_isolation`*

## 9. Auto-mitigation

- Not every case needs a human. Let's launch a lower-severity attack: hundreds of failed SSH logins from a known-bad IP address.  
  *On screen: `launch_ssh`*
- Threat intel confirms the IP is malicious, but the case is only medium severity, and nothing got in.  
  *On screen: `wait_run_done`*
- So the Response agent blocks the IP by itself. The action shows as executed automatically by policy, with no approval needed and no email sent.  
  *On screen: `scroll_actions`*
- Disruptive actions, like isolating a host or disabling an account, and anything on a business-critical asset, still always wait for a human.

## 10. False positives

- The agents also filter out noise. This is an authorized vulnerability scan during an approved penetration test window.  
  *On screen: `launch_scan`*
- Triage finds the scanner in the knowledge base whitelist, so the Supervisor skips investigation and response. The case closes as a false positive, with no actions.  
  *On screen: `wait_run_done`*

## 11. Auditor

- Now Vikram, the auditor.  
  *On screen: `login_auditor`*
- The decision trail records every agent run: what triggered it, which model or engine ran each step, the confidence, the duration and the tokens used.  
  *On screen: `goto_runs`*
- The audit log records every human and system change. The auditor can see everything, but cannot change anything.  
  *On screen: `goto_audit`*

## 12. SOC admin

- Finally, the SOC admin.  
  *On screen: `login_admin`*
- The admin console shows platform health, the background workers, and the team by role.  
  *On screen: `scroll_admin`*
- Under Users and Roles, the admin adds teammates with their email address, chooses their role, and decides who receives alert emails.  
  *On screen: `goto_users`*
- In the Agent Monitor, the admin manages the language models. Each provider has its own API key, and the arrows set the priority order.  
  *On screen: `goto_agents`*
- The agents use the top provider first. If it fails, runs out of credits, or is unreachable, they fall back to the next one, and finally to the offline engine.
- Platform settings choose the agent mode: auto, online only, or fully offline.  
  *On screen: `goto_settings`*

## 13. Summary

- To sum up. Alerts become cases automatically, seven AI agents investigate each one in seconds, and low-risk threats are contained without waiting.  
  *On screen: `card_summary`*
- People stay in control of every disruptive action through role-based approvals, the right teammates are emailed when something serious happens, and every decision is auditable.
- Thank you. We're happy to take your questions.
