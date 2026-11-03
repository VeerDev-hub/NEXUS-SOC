import { Bot, Crosshair, FileText, Globe, Network, Server, ShieldCheck, Workflow, type LucideIcon } from "lucide-react";
import type { AgentKey } from "./types";

export interface AgentMeta {
  key: AgentKey;
  name: string;
  short: string;
  icon: LucideIcon;
}

export const AGENT_META: Record<AgentKey, AgentMeta> = {
  supervisor: { key: "supervisor", name: "Supervisor", short: "Supervisor", icon: Workflow },
  triage: { key: "triage", name: "Triage Agent", short: "Triage", icon: Crosshair },
  threat_intel: { key: "threat_intel", name: "Threat Intel Agent", short: "Threat Intel", icon: Globe },
  asset_context: { key: "asset_context", name: "Asset & Identity Agent", short: "Asset Context", icon: Server },
  investigation: { key: "investigation", name: "Investigation Agent", short: "Investigation", icon: Network },
  response: { key: "response", name: "Response Agent", short: "Response", icon: ShieldCheck },
  reporting: { key: "reporting", name: "Reporting Agent", short: "Reporting", icon: FileText },
};

export const SPECIALISTS: AgentKey[] = ["triage", "threat_intel", "asset_context", "investigation", "response", "reporting"];

export function agentMeta(key: string): AgentMeta {
  return AGENT_META[key as AgentKey] ?? { key: key as AgentKey, name: key, short: key, icon: Bot };
}

export const TOOL_LABEL: Record<string, string> = {
  "threat_intel.lookup": "Threat intel lookup",
  "cmdb.lookup": "CMDB lookup",
  "siem.search": "Log search",
  "knowledge.search": "Knowledge base",
  "cases.related": "Related cases",
  "actions.propose": "Action catalogue",
};

export const ROLE_REQUIREMENT_LABEL: Record<string, string> = {
  "": "Auto (policy)",
  tier2_responder: "Tier-2 Responder",
  soc_manager: "SOC Manager",
};
