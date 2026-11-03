"use client";

import { useQuery } from "@tanstack/react-query";
import { get } from "./api";
import type { ActionProposal, AgentInfo, AgentRun, Alert, Artifact, Case, Enrichment, LLMStatus, Paginated } from "./types";

type Filters = Record<string, string | number | undefined>;

export const useCases = (filters: Filters = {}, refetchInterval?: number) =>
  useQuery({
    queryKey: ["cases", filters],
    queryFn: () => get<Paginated<Case>>("/cases", { page_size: 50, ordering: "-created_at", ...filters }),
    refetchInterval,
  });

export const useCase = (id: string) => useQuery({ queryKey: ["case", id], queryFn: () => get<Case>(`/cases/${id}`) });

export const useCaseAlerts = (id: string) =>
  useQuery({ queryKey: ["alerts", id], queryFn: () => get<Paginated<Alert>>("/alerts", { case__id: id, page_size: 50 }) });

export const useCaseArtifacts = (id: string) =>
  useQuery({ queryKey: ["artifacts", id], queryFn: () => get<Paginated<Artifact>>("/artifacts", { alerts__case: id, page_size: 100 }) });

export const useCaseEnrichments = (id: string) =>
  useQuery({ queryKey: ["enrichments", id], queryFn: () => get<Paginated<Enrichment>>("/enrichments", { case: id, page_size: 50 }) });

export const useCaseRuns = (id: string) =>
  useQuery({ queryKey: ["runs", "case", id], queryFn: () => get<AgentRun[]>(`/cases/${id}/agent-runs`) });

export const useRun = (id?: string) =>
  useQuery({
    queryKey: ["run", id],
    queryFn: () => get<AgentRun>(`/agent-runs/${id}`),
    enabled: !!id,
    // WebSocket pushes steps live; polling is only a safety net while running.
    refetchInterval: (q) => (q.state.data?.status === "Running" ? 4000 : false),
  });

export const useRuns = (filters: Filters = {}) =>
  useQuery({ queryKey: ["runs", filters], queryFn: () => get<Paginated<AgentRun>>("/agent-runs", { page_size: 50, ordering: "-started_at", ...filters }) });

export const useProposals = (filters: Filters = {}) =>
  useQuery({
    queryKey: ["proposals", filters],
    queryFn: () => get<Paginated<ActionProposal>>("/action-proposals", { page_size: 100, ordering: "-created_at", ...filters }),
  });

export const useAgentCatalog = () =>
  useQuery({ queryKey: ["agent-catalog"], queryFn: () => get<{ agents: AgentInfo[]; actions: unknown[]; llm: LLMStatus }>("/agents") });

export interface SocMetrics {
  cases: {
    total: number;
    open: number;
    critical_open: number;
    unassigned_open: number;
    by_severity: { severity: string; count: number }[];
    by_status: Record<string, number>;
    by_tier: { L1: number; L2: number };
    auto_escalated: number;
    closed_24h: number;
  };
  alerts: { last_24h: number; trend: { hour: string; alerts: number }[] };
  timings: { mttr_seconds: number | null; mtta_seconds: number | null; ai_triage_seconds: number | null };
  ai: { runs_total: number; runs_24h: number; reviewed_cases: number; agreement_rate: number | null; verdicts: { final_verdict: string; count: number }[] };
  actions: { pending: number; executed: number; rejected: number; auto_approved: number };
  workload: { user: string; username: string; role: string; open_cases: number }[];
  top_techniques: { technique: string; count: number }[];
  charts: {
    cases_daily: { day: string; Critical: number; High: number; Medium: number; Low: number; total: number }[];
    resolution_daily: { day: string; closed: number; mttr_hours: number | null }[];
    open_by_severity: { severity: string; count: number }[];
    pipeline: { status: string; count: number }[];
    alert_sources: { source: string; count: number }[];
    tactic_heatmap: { tactic: string; Critical: number; High: number; Medium: number; Low: number }[];
    verdict_pairs: { verdict_ai: string; verdict: string; count: number }[];
  };
}

export const useMetrics = () =>
  useQuery({ queryKey: ["metrics"], queryFn: () => get<SocMetrics>("/dashboard/soc-metrics"), refetchInterval: 30_000 });

export interface AgentMetrics {
  agents: { agent: string; runs: number; completed: number; failed: number; offline: number; avg_latency_ms: number | null; tokens: number | null; avg_confidence: number | null }[];
  runs: { total: number; completed: number; failed: number; running: number; tokens: number | null };
}

export const useAgentMetrics = () =>
  useQuery({ queryKey: ["metrics", "agents"], queryFn: () => get<AgentMetrics>("/agents/metrics"), refetchInterval: 30_000 });
