"use client";

import Link from "next/link";
import { BriefcaseBusiness, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import CaseTable from "@/components/CaseTable";
import LaunchScenario from "@/components/LaunchScenario";
import SocPosture from "@/components/SocPosture";
import ProposalCard, { canApprove } from "@/components/agents/ProposalCard";
import { Card, Empty, PageHeader, Spinner, StatTile } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { displayName, formatNumber } from "@/lib/format";
import { useCases, useMetrics, useProposals } from "@/lib/queries";

const OPEN = (s: string) => s !== "Resolved" && s !== "Closed";

export default function ResponderDesk() {
  const user = useAuth((s) => s.user);
  const l2 = useCases({ tier: "L2" }, 20_000);
  const proposals = useProposals({ status: "Pending" });
  const metrics = useMetrics();

  const queue = (l2.data?.results ?? []).filter((c) => OPEN(c.status));
  const mine = queue.filter((c) => c.assignee === user?.id);
  const pending = proposals.data?.results ?? [];
  const RISK = { Critical: 0, High: 1, Medium: 2, Low: 3 } as const;
  const byRisk = (a: (typeof pending)[number], b: (typeof pending)[number]) => RISK[a.risk_level] - RISK[b.risk_level];
  const actionable = pending.filter((p) => canApprove(user?.role, p)).sort(byRisk);
  const SHOWN = 6;
  const waiting = pending.filter((p) => !canApprove(user?.role, p));

  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader
        title={`Responder desk · ${displayName(user)}`}
        subtitle="Escalated incidents and the containment actions the Response Agent wants you to approve."
        actions={<LaunchScenario />}
      />
      <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Awaiting your approval" value={formatNumber(actionable.length)} icon={<ShieldAlert className="size-4" />} tone={actionable.length ? "warning" : undefined} />
        <StatTile label="Tier-2 queue" value={formatNumber(queue.length)} icon={<BriefcaseBusiness className="size-4" />} hint={`${mine.length} assigned to you`} />
        <StatTile label="Auto-escalated by AI" value={formatNumber(metrics.data?.cases.auto_escalated)} icon={<Zap className="size-4" />} hint="Confirmed High/Critical incidents" />
        <StatTile label="Actions executed" value={formatNumber(metrics.data?.actions.executed)} icon={<ShieldCheck className="size-4" />} hint={`${metrics.data?.actions.auto_approved ?? 0} low-risk auto-approved`} tone="good" />
      </div>

      <div className="mb-5">
        <SocPosture compact />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="space-y-5">
          <Card title="Tier-2 queue" bodyClassName="p-0">
            {l2.isLoading ? <Spinner /> : <CaseTable cases={queue} showTier={false} emptyTitle="No escalated incidents" />}
          </Card>
        </div>
        <div className="space-y-5">
          <Card title="Approvals for you">
            {proposals.isLoading ? (
              <Spinner />
            ) : actionable.length ? (
              <div className="space-y-3">
                {actionable.slice(0, SHOWN).map((p) => (
                  <ProposalCard key={p.id} proposal={p} showCase />
                ))}
                {actionable.length > SHOWN && (
                  <Link href="/approvals" className="block rounded-md border border-line py-2 text-center text-sm text-[#8fbcf3] hover:bg-panel-2">
                    View all {actionable.length} in the Approvals center
                  </Link>
                )}
              </div>
            ) : (
              <Empty title="Nothing to approve" icon={<ShieldCheck className="size-7" />} />
            )}
          </Card>
          {waiting.length > 0 && (
            <Card title="Waiting on the SOC Manager">
              <div className="space-y-3">
                {waiting.slice(0, 3).map((p) => (
                  <ProposalCard key={p.id} proposal={p} showCase />
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
