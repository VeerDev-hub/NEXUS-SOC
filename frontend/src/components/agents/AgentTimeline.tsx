"use client";

import { useState } from "react";
import { AlertTriangle, ArrowRight, ChevronDown, ChevronRight, CircleDashed, Clock, Coins, Loader2, Wrench } from "lucide-react";
import { agentMeta, TOOL_LABEL } from "@/lib/agents";
import { formatDuration, formatTime } from "@/lib/format";
import type { AgentStep } from "@/lib/types";
import { Badge, cx, ModeBadge, SeverityBadge, VerdictBadge } from "../ui";

/* eslint-disable @typescript-eslint/no-explicit-any */

function RoutingRow({ step }: { step: AgentStep }) {
  const next = step.output?.next_agent as string | undefined;
  const running = step.status === "Running";
  return (
    <li className="relative flex gap-3 pl-1">
      <div className="z-10 mt-1 flex size-6 shrink-0 items-center justify-center rounded-full border border-line-strong bg-bg">
        {running ? <Loader2 className="size-3 animate-spin text-accent" /> : <CircleDashed className="size-3 text-ink-3" />}
      </div>
      <div className="min-w-0 flex-1 pb-3 text-xs">
        <div className="flex flex-wrap items-center gap-2 text-ink-3">
          <span className="font-medium text-ink-2">Supervisor</span>
          {running ? (
            <span>deciding the next step...</span>
          ) : (
            <>
              <ArrowRight className="size-3" />
              <span className="font-medium text-ink">{next === "finish" ? "Finish" : agentMeta(next ?? "").name}</span>
              {step.output?.overridden && <Badge tone="warning">guardrail override</Badge>}
              {step.llm_mode === "online" && <Badge tone="accent">LLM routed</Badge>}
            </>
          )}
          <span className="ml-auto">{formatTime(step.started_at)}</span>
        </div>
        {step.routing_reason && <p className="mt-0.5 text-ink-3 italic">&ldquo;{step.routing_reason}&rdquo;</p>}
      </div>
    </li>
  );
}

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex gap-2 text-xs">
      <span className="w-28 shrink-0 text-ink-3">{k}</span>
      <span className="min-w-0 text-ink-2">{v}</span>
    </div>
  );
}

function AgentOutput({ step }: { step: AgentStep }) {
  const o = step.output as any;
  switch (step.agent) {
    case "triage":
      return (
        <div className="space-y-1.5">
          <KV k="Classification" v={o.classification} />
          <KV k="Verdict" v={<VerdictBadge value={o.verdict} />} />
          <KV k="Severity" v={<SeverityBadge value={o.severity} />} />
          {o.false_positive_indicators?.length > 0 && <KV k="FP indicators" v={o.false_positive_indicators.join(", ")} />}
          {o.is_duplicate && <KV k="Duplicate" v="Likely duplicate of an open case" />}
          <ul className="ml-4 list-disc text-xs text-ink-3">
            {(o.key_observations ?? []).map((x: string, i: number) => (
              <li key={i}>{x}</li>
            ))}
          </ul>
        </div>
      );
    case "threat_intel":
      return (
        <div className="space-y-1">
          {(o.indicators ?? []).map((i: any) => (
            <div key={i.value} className="flex items-center gap-2 text-xs">
              <Badge tone={i.reputation === "malicious" ? "critical" : i.reputation === "suspicious" ? "warning" : i.reputation === "clean" ? "good" : "neutral"}>
                {i.reputation}
              </Badge>
              <code className="truncate text-ink-2">{i.value}</code>
              <span className="truncate text-ink-3">{i.context}</span>
            </div>
          ))}
          {!o.indicators?.length && <div className="text-xs text-ink-3">No external indicators.</div>}
        </div>
      );
    case "asset_context":
      return (
        <div className="space-y-1">
          {(o.entities ?? []).map((e: any) => (
            <div key={e.name} className="flex items-center gap-2 text-xs">
              <Badge tone={e.criticality === "Critical" ? "critical" : e.criticality === "High" ? "serious" : "neutral"}>{e.criticality}</Badge>
              <code className="text-ink-2">{e.name}</code>
              <span className="text-ink-3">
                {e.entity_type} · {e.owner || "unknown owner"}
              </span>
            </div>
          ))}
          <p className="pt-1 text-xs text-ink-3">{o.blast_radius}</p>
        </div>
      );
    case "investigation":
      return (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1.5">
            {(o.mitre_techniques ?? []).map((t: any) => (
              <Badge key={t.technique_id} tone="accent">
                {t.technique_id} {t.name}
              </Badge>
            ))}
          </div>
          <KV k="Verdict" v={<VerdictBadge value={o.verdict} />} />
          <KV k="Scope" v={o.scope} />
          {o.unknowns?.length > 0 && <KV k="Open questions" v={o.unknowns.join(" ")} />}
        </div>
      );
    case "response":
      return (
        <div className="space-y-1">
          <p className="text-xs text-ink-3">{o.containment_strategy}</p>
          {(o.actions ?? []).map((a: any) => (
            <div key={a.action_type + a.target} className="flex items-center gap-2 text-xs">
              <code className="text-[#8fbcf3]">{a.action_type}</code>
              <ArrowRight className="size-3 text-ink-3" />
              <code className="truncate text-ink-2">{a.target}</code>
            </div>
          ))}
        </div>
      );
    case "reporting":
      return (
        <div className="flex flex-wrap gap-2">
          <VerdictBadge value={o.verdict} />
          <SeverityBadge value={o.severity} />
          <Badge>Impact {o.impact}</Badge>
          <Badge>Confidence {o.confidence}</Badge>
        </div>
      );
    default:
      return null;
  }
}

function AgentCard({ step, highlighted }: { step: AgentStep; highlighted?: boolean }) {
  const [open, setOpen] = useState(false);
  const meta = agentMeta(step.agent);
  const Icon = meta.icon;
  const running = step.status === "Running";
  const failed = step.status === "Failed";
  return (
    <li id={`step-${step.id}`} className="relative flex gap-3">
      <div
        className={cx(
          "z-10 flex size-8 shrink-0 items-center justify-center rounded-full border-2 bg-panel",
          running ? "border-accent animate-pulse-ring" : failed ? "border-critical" : "border-[#199e70]",
        )}
      >
        {running ? <Loader2 className="size-4 animate-spin text-accent" /> : <Icon className={cx("size-4", failed ? "text-critical" : "text-[#3ec796]")} />}
      </div>
      <div className={cx("mb-4 min-w-0 flex-1 rounded-lg border bg-panel-2 p-3", highlighted ? "border-accent" : "border-line")}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold">{meta.name}</span>
          {!running && <ModeBadge mode={step.llm_mode} />}
          {step.confidence != null && <Badge tone="accent">{step.confidence}% confidence</Badge>}
          <span className="ml-auto flex items-center gap-3 text-[11px] text-ink-3">
            <span className="flex items-center gap-1">
              <Clock className="size-3" />
              {running ? "running" : formatDuration(step.latency_ms)}
            </span>
            {step.tokens_in + step.tokens_out > 0 && (
              <span className="flex items-center gap-1">
                <Coins className="size-3" />
                {step.tokens_in + step.tokens_out} tok
              </span>
            )}
          </span>
        </div>

        {running ? (
          <p className="mt-2 text-xs text-ink-3">Working on the case...</p>
        ) : failed ? (
          <p className="mt-2 flex items-center gap-1.5 text-xs text-[#f3a5a5]">
            <AlertTriangle className="size-3.5" /> {step.error}
          </p>
        ) : (
          <>
            <p className="mt-2 text-sm leading-relaxed text-ink-2">{step.summary}</p>
            <div className="mt-3">
              <AgentOutput step={step} />
            </div>
          </>
        )}

        {(step.tool_calls?.length > 0 || step.fallback_reason || step.provider) && !running && (
          <div className="mt-3 border-t border-line pt-2">
            <button onClick={() => setOpen(!open)} className="flex items-center gap-1 text-xs text-ink-3 hover:text-ink-2">
              {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
              <Wrench className="size-3" /> {step.tool_calls.length} tool call{step.tool_calls.length === 1 ? "" : "s"} · {step.provider || "policy"}
              {step.model ? ` / ${step.model}` : ""}
            </button>
            {open && (
              <div className="mt-2 space-y-1.5">
                {step.tool_calls.map((t, i) => (
                  <div key={i} className="rounded border border-line bg-bg px-2 py-1.5 font-mono text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className={t.status === "ok" ? "text-[#3ec796]" : "text-critical"}>{t.status === "ok" ? "✓" : "✗"}</span>
                      <span className="text-ink">{TOOL_LABEL[t.tool] ?? t.tool}</span>
                      <span className="truncate text-ink-3">{Object.values(t.args ?? {}).map(String).join(", ")}</span>
                      <span className="ml-auto text-ink-3">{t.latency_ms} ms</span>
                    </div>
                    <div className="mt-0.5 text-ink-3">{t.summary}</div>
                  </div>
                ))}
                {step.fallback_reason && (
                  <div className="text-[11px] text-warning">Offline fallback: {step.fallback_reason}</div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

export default function AgentTimeline({ steps, highlightId, showRouting = true }: { steps: AgentStep[]; highlightId?: string; showRouting?: boolean }) {
  const visible = showRouting ? steps : steps.filter((s) => s.agent !== "supervisor");
  return (
    <ol className="relative">
      <span className="absolute bottom-4 left-[15px] top-2 w-px bg-line" aria-hidden />
      {visible.map((step) =>
        step.agent === "supervisor" ? <RoutingRow key={step.id} step={step} /> : <AgentCard key={step.id} step={step} highlighted={step.id === highlightId} />,
      )}
    </ol>
  );
}
