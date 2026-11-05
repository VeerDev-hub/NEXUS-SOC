export type Role = "admin" | "soc_manager" | "tier1_analyst" | "tier2_responder" | "auditor";

export type Permission =
  | "dashboard.view"
  | "dashboard.team"
  | "records.view"
  | "records.write"
  | "records.delete"
  | "cases.escalate"
  | "cases.close"
  | "agents.view"
  | "agents.run"
  | "actions.view"
  | "actions.approve"
  | "knowledge.write"
  | "reports.view"
  | "audit.view"
  | "settings.manage"
  | "users.manage";

export interface User {
  id: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  title: string;
  role: Role;
  role_label: string;
  permissions: Permission[];
  is_active: boolean;
  last_login: string | null;
  date_joined: string;
  email_alerts?: boolean;
  notify_on_case_assignment?: boolean;
}

export interface Paginated<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational" | "Unknown" | "";

export interface Case {
  id: string;
  case_id: string;
  title: string;
  severity: Severity;
  impact: string;
  priority: string;
  confidence: string;
  description: string;
  category: string;
  tags: string[];
  status: "New" | "In Progress" | "On Hold" | "Resolved" | "Closed";
  verdict: string;
  summary: string;
  assignee: number | null;
  assignee_name: string;
  tier: "L1" | "L2";
  escalated_at: string | null;
  escalated_by_name: string;
  escalation_reason: string;
  severity_ai: Severity;
  confidence_ai: string;
  impact_ai: string;
  priority_ai: string;
  verdict_ai: string;
  alert_count?: number;
  enrichment_count?: number;
  created_at: string;
  updated_at: string;
  closed_time: string | null;
}

export interface Alert {
  id: string;
  alert_id: string;
  title: string;
  severity: Severity;
  confidence: string;
  desc: string;
  rule_name: string;
  tactic: string;
  technique: string;
  product_name: string;
  product_vendor: string;
  first_seen_time: string | null;
  status: string;
  labels: string[];
  raw_data: Record<string, unknown>;
  case_readable_id?: string;
  case_title?: string;
  case: string;
}

export interface Artifact {
  id: string;
  artifact_id: string;
  name: string;
  type: string;
  role: string;
  value: string;
}

export interface Enrichment {
  id: string;
  name: string;
  type: string;
  provider: string;
  value: string;
  desc: string;
  data: Record<string, unknown>;
}

export interface ToolCall {
  tool: string;
  args: Record<string, unknown>;
  status: "ok" | "error";
  summary: string;
  latency_ms: number;
}

export type AgentKey = "supervisor" | "triage" | "threat_intel" | "asset_context" | "investigation" | "response" | "reporting";

export interface AgentStep {
  id: string;
  sequence: number;
  agent: AgentKey;
  status: "Running" | "Completed" | "Failed" | "Skipped";
  routing_reason: string;
  summary: string;
  output: Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  tool_calls: ToolCall[];
  confidence: number | null;
  llm_mode: "online" | "offline" | "";
  provider: string;
  model: string;
  fallback_reason: string;
  tokens_in: number;
  tokens_out: number;
  latency_ms: number;
  started_at: string;
  completed_at: string | null;
  error: string;
}

export interface UserRef {
  id: number;
  username: string;
  name: string;
}

export interface ActionProposal {
  id: string;
  case_pk: string;
  case_id: string;
  case_title: string;
  run: string | null;
  action_type: string;
  action_label: string;
  connector: string;
  target: string;
  rationale: string;
  risk_level: "Low" | "Medium" | "High" | "Critical";
  required_role: "" | "tier2_responder" | "soc_manager";
  status: "Pending" | "Approved" | "Rejected" | "Executed" | "Failed";
  auto_approved: boolean;
  decided_by: UserRef | null;
  decided_at: string | null;
  decision_note: string;
  executed_at: string | null;
  execution_result: Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  created_at: string;
}

export interface FinalReport {
  verdict: string;
  severity: string;
  impact: string;
  priority: string;
  confidence: string;
  executive_summary: string;
  digest: string;
  affected_assets: { asset_type: string; asset_value: string }[];
  evidence_findings: { title: string; finding_type: string; subject: string; evidence: string; conclusion: string }[];
  attack_chain: { attack_stage: string; description: string }[];
  attack_timeline: { timestamp: string; attack_behavior: string; evidence_field: string }[];
  ioc_indicators: { indicator_type: string; value: string; context: string }[];
  remediations: { action_type: string; description: string; priority: string }[];
  unknowns: string[];
}

export interface AgentRun {
  id: string;
  case_pk: string;
  case_id: string;
  case_title: string;
  status: "Running" | "Completed" | "Failed";
  trigger: string;
  triggered_by: UserRef | null;
  llm_mode: "online" | "offline" | "mixed" | "";
  current_agent: string;
  final_verdict: string;
  final_severity: string;
  final_confidence: number | null;
  summary: string;
  total_tokens: number;
  started_at: string;
  completed_at: string | null;
  duration_ms: number | null;
  error: string;
  user_input?: string;
  report?: Partial<FinalReport>;
  steps?: AgentStep[];
  proposals?: ActionProposal[];
}

export interface LLMStatus {
  configured_mode: "auto" | "online" | "offline";
  effective_mode: "online" | "offline";
  detail: string;
  providers: { name: string; provider: string; provider_label: string; model: string; tags: string[] }[];
}

export interface AgentInfo {
  key: AgentKey;
  name: string;
  description: string;
  tools: string[];
}

export interface Comment {
  id: number;
  message: string;
  author_name?: string;
  author?: { username: string; name?: string } | number | null;
  created_at: string;
}
