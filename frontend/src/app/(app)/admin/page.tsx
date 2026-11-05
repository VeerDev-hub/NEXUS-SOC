"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Bot, Cpu, Server, Settings, Users } from "lucide-react";
import { RequirePermission } from "@/components/AppShell";
import AssignWorkPanel from "@/components/AssignWorkPanel";
import LaunchScenario from "@/components/LaunchScenario";
import RunFeed from "@/components/RunFeed";
import SocPosture from "@/components/SocPosture";
import { Badge, Button, Card, PageHeader, Spinner, StatTile, Table } from "@/components/ui";
import { get } from "@/lib/api";
import { ROLE_LABEL } from "@/lib/auth";
import { formatNumber, timeAgo } from "@/lib/format";
import { useAgentCatalog, useMetrics } from "@/lib/queries";
import type { Paginated, Role, User } from "@/lib/types";

interface Worker {
  worker_type?: string;
  worker_name?: string;
  name?: string;
  status?: string;
  hostname?: string;
  last_seen_at?: string;
  heartbeat_at?: string;
}

export default function AdminConsole() {
  return (
    <RequirePermission perm="settings.manage">
      <Console />
    </RequirePermission>
  );
}

function Console() {
  const catalog = useAgentCatalog();
  const metrics = useMetrics();
  const users = useQuery({ queryKey: ["users"], queryFn: () => get<Paginated<User>>("/auth/users", { page_size: 100 }) });
  const workers = useQuery({ queryKey: ["workers"], queryFn: () => get<{ results: Worker[] }>("/settings/workers"), refetchInterval: 15_000, retry: false });

  if (catalog.isLoading) return <Spinner />;
  const llm = catalog.data!.llm;
  const byRole = (users.data?.results ?? []).reduce<Record<string, number>>((acc, u) => ((acc[u.role] = (acc[u.role] ?? 0) + 1), acc), {});

  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader
        title="Admin console"
        subtitle="Platform health, people and AI configuration."
        actions={
          <>
            <LaunchScenario />
            <Link href="/admin/settings">
              <Button icon={<Settings className="size-4" />}>Settings</Button>
            </Link>
          </>
        }
      />
      <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="LLM"
          value={llm.effective_mode === "online" ? "Online" : "Offline"}
          icon={<Cpu className="size-4" />}
          tone={llm.effective_mode === "online" ? "good" : "warning"}
          hint={llm.providers[0] ? `${llm.providers[0].provider_label} · ${llm.providers[0].model}` : "No provider configured"}
        />
        <StatTile label="Agents" value={catalog.data!.agents.length} icon={<Bot className="size-4" />} hint="Supervisor + 6 specialists" />
        <StatTile label="Users" value={formatNumber(users.data?.count)} icon={<Users className="size-4" />} hint={`${byRole.tier1_analyst ?? 0} Tier-1 · ${byRole.tier2_responder ?? 0} Tier-2`} />
        <StatTile label="Open cases" value={formatNumber(metrics.data?.cases.open)} icon={<Server className="size-4" />} />
      </div>

      <div className="mb-5">
        <SocPosture compact />
      </div>

      <AssignWorkPanel className="mb-5" />

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Background workers" className="xl:col-span-2" bodyClassName="p-0">
          {workers.error ? (
            <div className="p-4 text-sm text-ink-3">Worker health is unavailable (Redis not reachable).</div>
          ) : workers.isLoading ? (
            <Spinner />
          ) : (
            <Table head={["Worker", "Host", "Status", "Last heartbeat"]}>
              {(workers.data?.results ?? []).map((w, i) => (
                <tr key={i}>
                  <td className="px-3 py-2 text-sm">{w.worker_name ?? w.name ?? w.worker_type}</td>
                  <td className="px-3 py-2 text-xs text-ink-3">{w.hostname ?? "-"}</td>
                  <td className="px-3 py-2">
                    <Badge tone={w.status === "running" || w.status === "healthy" || w.status === "idle" ? "good" : "warning"}>{w.status ?? "unknown"}</Badge>
                  </td>
                  <td className="px-3 py-2 text-xs text-ink-3">{timeAgo(w.last_seen_at ?? w.heartbeat_at)}</td>
                </tr>
              ))}
              {!workers.data?.results.length && (
                <tr>
                  <td colSpan={4} className="px-3 py-4 text-sm text-ink-3">
                    No workers reporting. Start the agent worker to process cases.
                  </td>
                </tr>
              )}
            </Table>
          )}
        </Card>
        <Card title="Team by role" action={<Link href="/admin/users" className="text-xs text-[#8fbcf3] hover:underline">Manage</Link>}>
          <ul className="space-y-2 text-sm">
            {(Object.keys(ROLE_LABEL) as Role[]).map((r) => (
              <li key={r} className="flex justify-between">
                <span className="text-ink-2">{ROLE_LABEL[r]}</span>
                <span className="tabular-nums text-ink-3">{byRole[r] ?? 0}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
      <Card title="Recent agent runs" className="mt-5">
        <RunFeed limit={6} />
      </Card>
    </div>
  );
}
