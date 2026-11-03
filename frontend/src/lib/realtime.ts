"use client";

import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { create } from "zustand";
import { useAuth } from "./auth";
import { toast } from "./toast";
import type { ActionProposal, AgentRun, AgentStep } from "./types";

interface RealtimeState {
  connected: boolean;
  lastEventAt: number | null;
  set: (s: Partial<RealtimeState>) => void;
}

export const useRealtimeStatus = create<RealtimeState>((set) => ({ connected: false, lastEventAt: null, set }));

function wsUrl(token: string) {
  // Explicit URL (dev), otherwise the backend on the same host at port 8000 (Docker Compose).
  const configured = process.env.NEXT_PUBLIC_WS_URL;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const base = configured || `${proto}//${location.hostname}:${process.env.NEXT_PUBLIC_BACKEND_PORT ?? "8000"}/ws/events/`;
  return `${base}?token=${encodeURIComponent(token)}`;
}

function upsertStep(qc: QueryClient, runId: string, step: AgentStep) {
  qc.setQueryData<AgentRun>(["run", runId], (run) => {
    if (!run) return run;
    const steps = [...(run.steps ?? [])];
    const i = steps.findIndex((s) => s.id === step.id);
    if (i >= 0) steps[i] = step;
    else steps.push(step);
    steps.sort((a, b) => a.sequence - b.sequence);
    return { ...run, steps, current_agent: step.status === "Running" ? step.agent : run.current_agent };
  });
}

type Envelope = { type: string; payload: Record<string, unknown> };

function handle(qc: QueryClient, event: Envelope) {
  const p = event.payload ?? {};
  switch (event.type) {
    case "agent.run.started":
    case "agent.run.completed": {
      const run = p.run as AgentRun;
      qc.setQueryData<AgentRun>(["run", run.id], (old) => (old ? { ...old, ...run } : old));
      qc.invalidateQueries({ queryKey: ["runs"] });
      qc.invalidateQueries({ queryKey: ["case", run.case_pk] });
      qc.invalidateQueries({ queryKey: ["cases"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
      if (event.type === "agent.run.completed") {
        qc.invalidateQueries({ queryKey: ["run", run.id] });
        qc.invalidateQueries({ queryKey: ["enrichments", run.case_pk] });
        toast(
          run.status === "Completed"
            ? `${run.case_id.toUpperCase()}: agents finished - ${run.final_verdict || "no verdict"}`
            : `${run.case_id.toUpperCase()}: agent run failed`,
          run.status === "Completed" ? "info" : "error",
        );
      } else {
        toast(`${run.case_id.toUpperCase()}: AI agent team started`, "info");
      }
      break;
    }
    case "agent.step.started":
    case "agent.step.completed":
      upsertStep(qc, p.run_id as string, p.step as AgentStep);
      break;
    case "agent.proposal.created":
    case "agent.proposal.updated": {
      const proposal = p.proposal as ActionProposal;
      qc.invalidateQueries({ queryKey: ["proposals"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
      if (event.type === "agent.proposal.created" && proposal.status === "Pending") {
        toast(`Approval needed: ${proposal.action_label} on ${proposal.target}`, "warning");
      }
      break;
    }
  }
}

/** One WebSocket per session; reconnects with backoff. */
export function useRealtime() {
  const qc = useQueryClient();
  const access = useAuth((s) => s.access);
  const setStatus = useRealtimeStatus((s) => s.set);

  useEffect(() => {
    if (!access) return;
    let socket: WebSocket | null = null;
    let stopped = false;
    let attempt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      socket = new WebSocket(wsUrl(access));
      socket.onopen = () => {
        attempt = 0;
        setStatus({ connected: true });
      };
      socket.onmessage = (msg) => {
        try {
          const event = JSON.parse(msg.data) as Envelope;
          setStatus({ lastEventAt: Date.now() });
          handle(qc, event);
        } catch {
          /* ignore malformed frames */
        }
      };
      socket.onclose = () => {
        setStatus({ connected: false });
        if (stopped) return;
        attempt += 1;
        timer = setTimeout(connect, Math.min(15000, 1000 * 2 ** attempt));
      };
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      socket?.close();
    };
  }, [access, qc, setStatus]);
}
