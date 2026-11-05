"use client";

import { Activity, Bot, Cpu, Gauge, WifiOff } from "lucide-react";
import { HorizontalBars } from "@/components/charts";
import LLMProvidersPanel from "@/components/agents/LLMProvidersPanel";
import RunFeed from "@/components/RunFeed";
import { Badge, Card, PageHeader, Spinner, StatTile, Table } from "@/components/ui";
import { agentMeta, TOOL_LABEL } from "@/lib/agents";
import { can, useAuth } from "@/lib/auth";
import { formatDuration, formatNumber } from "@/lib/format";
import { useAgentCatalog, useAgentMetrics } from "@/lib/queries";

export default function AgentMonitor() {
  const catalog = useAgentCatalog();
  const metrics = useAgentMetrics();
  const canManage = can(useAuth((s) => s.user), "settings.manage");
  if (catalog.isLoading || metrics.isLoading) return <Spinner />;
  const llm = catalog.data!.llm;
  const byAgent = Object.fromEntries((metrics.data?.agents ?? []).map((a) => [a.agent, a]));
  const runs = metrics.data!.runs;
  const latency = (metrics.data?.agents ?? [])
    .filter((a) => a.agent !== "supervisor" && a.avg_latency_ms != null)
    .map((a) => ({ label: agentMeta(a.agent).short, value: Math.round(a.avg_latency_ms ?? 0) }));
  const steps = (metrics.data?.agents ?? []).reduce((n, a) => n + a.runs, 0);
  const offline = (metrics.data?.agents ?? []).reduce((n, a) => n + a.offline, 0);

  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader title="Agent monitor" subtitle="Health, throughput and model usage of the multi-agent team." />

      <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Agent runs" value={formatNumber(runs.total)} icon={<Activity className="size-4" />} hint={`${runs.running} running · ${runs.failed} failed`} />
        <StatTile label="Agent steps executed" value={formatNumber(steps)} icon={<Bot className="size-4" />} />
        <StatTile label="LLM tokens used" value={formatNumber(runs.tokens ?? 0)} icon={<Cpu className="size-4" />} />
        <StatTile label="Steps on offline engine" value={steps ? `${Math.round((100 * offline) / steps)}%` : "-"} icon={<WifiOff className="size-4" />} hint="Fallback when no LLM is reachable" />
      </div>

      <Card title="Language model" className="mb-5">
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <Badge tone={llm.effective_mode === "online" ? "good" : "warning"}>{llm.effective_mode === "online" ? "Online" : "Offline engine"}</Badge>
          <span className="text-ink-3">Configured mode: {llm.configured_mode}</span>
          <span className="text-ink-3">{llm.detail}</span>
        </div>
        {!canManage && llm.providers.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-2">
            {llm.providers.map((p, i) => (
              <span key={p.name} className="rounded border border-line-strong bg-bg px-2 py-1 text-xs">
                {i === 0 && <span className="mr-1 text-good">primary</span>}
                {p.provider_label} · <code>{p.model}</code>
                {p.tags.length > 0 && <span className="text-ink-3"> [{p.tags.join(", ")}]</span>}
              </span>
            ))}
          </div>
        )}
      </Card>

      {canManage && <LLMProvidersPanel className="mb-5" />}

      <Card title="Agent roster" className="mb-5" bodyClassName="p-0">
        <Table head={["Agent", "Role", "Tools", "Steps", "Success", "Avg latency", "Avg confidence", "Offline"]}>
          {catalog.data!.agents.map((a) => {
            const meta = agentMeta(a.key);
            const m = byAgent[a.key];
            return (
              <tr key={a.key}>
                <td className="whitespace-nowrap px-3 py-2.5">
                  <span className="flex items-center gap-2 font-medium">
                    <meta.icon className="size-4 text-accent" /> {a.name}
                  </span>
                </td>
                <td className="max-w-[360px] px-3 py-2.5 text-xs text-ink-3">{a.description}</td>
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {a.tools.map((t) => (
                      <Badge key={t}>{TOOL_LABEL[t] ?? t}</Badge>
                    ))}
                  </div>
                </td>
                <td className="px-3 py-2.5 tabular-nums">{m?.runs ?? 0}</td>
                <td className="px-3 py-2.5 tabular-nums">{m?.runs ? `${Math.round((100 * m.completed) / m.runs)}%` : "-"}</td>
                <td className="px-3 py-2.5 tabular-nums">{formatDuration(m?.avg_latency_ms != null ? Math.round(m.avg_latency_ms) : null)}</td>
                <td className="px-3 py-2.5 tabular-nums">{m?.avg_confidence != null ? `${Math.round(m.avg_confidence)}%` : "-"}</td>
                <td className="px-3 py-2.5 tabular-nums">{m?.runs ? `${Math.round((100 * m.offline) / m.runs)}%` : "-"}</td>
              </tr>
            );
          })}
        </Table>
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Average latency per agent (ms)">{latency.length ? <HorizontalBars data={latency} unit="ms" /> : <div className="text-sm text-ink-3">No data yet.</div>}</Card>
        <Card
          title={
            <span className="flex items-center gap-2">
              <Gauge className="size-4 text-ink-3" /> Recent runs
            </span>
          }
        >
          <RunFeed limit={10} />
        </Card>
      </div>
    </div>
  );
}
