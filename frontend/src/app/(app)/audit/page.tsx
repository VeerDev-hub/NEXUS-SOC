"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Bot, History, ShieldCheck, User } from "lucide-react";
import { RequirePermission } from "@/components/AppShell";
import RunFeed from "@/components/RunFeed";
import SocPosture from "@/components/SocPosture";
import { Badge, Card, cx, inputClass, PageHeader, Spinner, StatTile, Table } from "@/components/ui";
import { get } from "@/lib/api";
import { formatDateTime, formatNumber } from "@/lib/format";
import { useMetrics } from "@/lib/queries";

interface AuditEntry {
  id: number;
  readable_id: string;
  action: string;
  actor_name: string;
  resource_label: string;
  object_id: string;
  summary: string;
  field_summary: string;
  changes: Record<string, { from: unknown; to: unknown }>;
  created_at: string;
}

function short(v: unknown) {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s && s.length > 60 ? `${s.slice(0, 60)}...` : s ?? "-";
}

export default function AuditPage() {
  return (
    <RequirePermission perm="audit.view">
      <Audit />
    </RequirePermission>
  );
}

function Audit() {
  const [search, setSearch] = useState("");
  const metrics = useMetrics();
  const q = useQuery({
    queryKey: ["audit", search],
    queryFn: () => get<{ count: number; results: AuditEntry[] }>("/settings/audit-logs", { search, ordering: "-created_at", limit: 100 }),
  });
  const entries = (q.data?.results ?? []).slice(0, 100);

  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader title="Audit log" subtitle="Tamper-evident record of every change made by people and by the AI agents." />
      <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Audit entries" value={formatNumber(q.data?.count)} icon={<History className="size-4" />} />
        <StatTile label="Agent runs recorded" value={formatNumber(metrics.data?.ai.runs_total)} icon={<Bot className="size-4" />} />
        <StatTile label="Human-approved actions" value={formatNumber((metrics.data?.actions.executed ?? 0) - (metrics.data?.actions.auto_approved ?? 0))} icon={<User className="size-4" />} />
        <StatTile label="Policy auto-approved" value={formatNumber(metrics.data?.actions.auto_approved)} icon={<ShieldCheck className="size-4" />} hint="Low-risk actions only" />
      </div>
      <div className="mb-5">
        <SocPosture compact />
      </div>
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card bodyClassName="p-0">
          <div className="border-b border-line p-3">
            <input className={cx(inputClass, "max-w-sm")} placeholder="Search by user, record, field or value" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          {q.isLoading ? (
            <Spinner />
          ) : (
            <Table head={["When", "Who", "Action", "Record", "Changes"]}>
              {entries.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-3">{formatDateTime(e.created_at)}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs">
                    {e.actor_name ? (
                      <span className="flex items-center gap-1">
                        <User className="size-3 text-ink-3" />
                        {e.actor_name}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-ink-3">
                        <Bot className="size-3" /> system / agents
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <Badge tone={e.action === "delete" ? "critical" : e.action === "create" ? "good" : "neutral"}>{e.action}</Badge>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs">{e.resource_label}</td>
                  <td className="max-w-[420px] px-3 py-2 font-mono text-[11px] text-ink-3">
                    {Object.entries(e.changes ?? {})
                      .slice(0, 3)
                      .map(([k, v]) => (
                        <div key={k} className="truncate">
                          {k}: {short(v?.from)} → <span className="text-ink-2">{short(v?.to)}</span>
                        </div>
                      ))}
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
        <Card title="Latest agent decisions">
          <RunFeed limit={10} />
        </Card>
      </div>
    </div>
  );
}
