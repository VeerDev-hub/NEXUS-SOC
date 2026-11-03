"use client";

import { AlertOctagon, Bot, BriefcaseBusiness, Gauge, Handshake, ShieldAlert, Timer } from "lucide-react";
import ProposalCard from "@/components/agents/ProposalCard";
import { AlertTrendChart, HorizontalBars } from "@/components/charts";
import LaunchScenario from "@/components/LaunchScenario";
import RunFeed from "@/components/RunFeed";
import SocPosture from "@/components/SocPosture";
import { Card, Empty, PageHeader, Spinner, StatTile } from "@/components/ui";
import { RequirePermission } from "@/components/AppShell";
import { formatNumber, formatSeconds } from "@/lib/format";
import { useMetrics, useProposals } from "@/lib/queries";

export default function ManagerOverview() {
  return (
    <RequirePermission perm="dashboard.team">
      <Overview />
    </RequirePermission>
  );
}

function Overview() {
  const m = useMetrics();
  const critical = useProposals({ status: "Pending", required_role: "soc_manager" });
  if (m.isLoading || !m.data) return <Spinner />;
  const d = m.data;
  const verdicts = d.ai.verdicts.map((v) => ({ label: v.final_verdict || "Undetermined", value: v.count }));
  const workload = d.workload.map((w) => ({ label: w.user, value: w.open_cases }));

  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader title="SOC overview" subtitle="Live view of the human + AI team. Refreshes automatically." actions={<LaunchScenario />} />

      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
        <StatTile label="Open cases" value={formatNumber(d.cases.open)} icon={<BriefcaseBusiness className="size-4" />} hint={`${d.cases.by_tier.L1} Tier-1 · ${d.cases.by_tier.L2} Tier-2`} />
        <StatTile label="Critical open" value={formatNumber(d.cases.critical_open)} icon={<AlertOctagon className="size-4" />} tone={d.cases.critical_open ? "critical" : undefined} hint={`${d.cases.unassigned_open} unassigned overall`} />
        <StatTile label="AI triage time" value={d.timings.ai_triage_seconds != null ? `${d.timings.ai_triage_seconds}s` : "-"} icon={<Bot className="size-4" />} hint={`${d.ai.runs_24h} agent runs in 24h`} />
        <StatTile label="Mean time to resolve" value={formatSeconds(d.timings.mttr_seconds)} icon={<Timer className="size-4" />} hint={`${d.cases.closed_24h} closed in 24h`} />
        <StatTile
          label="AI / analyst agreement"
          value={d.ai.agreement_rate != null ? `${d.ai.agreement_rate}%` : "-"}
          icon={<Handshake className="size-4" />}
          hint={`${d.ai.reviewed_cases} cases with both verdicts`}
        />
        <StatTile label="Pending approvals" value={formatNumber(d.actions.pending)} icon={<ShieldAlert className="size-4" />} tone={d.actions.pending ? "warning" : undefined} hint={`${d.actions.executed} executed · ${d.actions.rejected} rejected`} />
      </div>

      <div className="mb-5">
        <SocPosture />
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Critical actions needing a manager">
          {critical.data?.results.length ? (
            <div className="space-y-3">
              {critical.data.results.map((p) => (
                <ProposalCard key={p.id} proposal={p} showCase />
              ))}
            </div>
          ) : (
            <Empty title="No critical approvals waiting" icon={<Gauge className="size-7" />} />
          )}
        </Card>
        <Card title="Live agent activity">
          <RunFeed />
        </Card>
        <div className="space-y-5">
          <Card title="Alerts ingested · last 24 hours">
            <AlertTrendChart data={d.alerts.trend} />
          </Card>
          <Card title="AI verdicts (completed runs)">{verdicts.length ? <HorizontalBars data={verdicts} unit="runs" /> : <Empty title="No runs yet" />}</Card>
          <Card title="Open cases per analyst">{workload.some((w) => w.value > 0) ? <HorizontalBars data={workload} unit="open cases" /> : <Empty title="No cases assigned yet">Analysts pick up cases with Assign to me.</Empty>}</Card>
          <Card title="Top ATT&CK techniques">
            <ul className="space-y-1.5 text-sm">
              {d.top_techniques.map((t) => (
                <li key={t.technique} className="flex justify-between gap-3">
                  <span className="truncate text-ink-2">{t.technique}</span>
                  <span className="tabular-nums text-ink-3">{t.count}</span>
                </li>
              ))}
              {!d.top_techniques.length && <li className="text-ink-3">No mapped techniques yet.</li>}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
