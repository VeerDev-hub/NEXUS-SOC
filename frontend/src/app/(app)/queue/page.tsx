"use client";

import { Bot, Inbox, Siren, Timer } from "lucide-react";
import CaseTable from "@/components/CaseTable";
import LaunchScenario from "@/components/LaunchScenario";
import SocPosture from "@/components/SocPosture";
import { Card, PageHeader, Spinner, StatTile } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { displayName, formatNumber } from "@/lib/format";
import { useCases, useMetrics } from "@/lib/queries";

const OPEN = (s: string) => s !== "Resolved" && s !== "Closed";

export default function Tier1Queue() {
  const user = useAuth((s) => s.user);
  const l1 = useCases({ tier: "L1" }, 20_000);
  const escalated = useCases({ tier: "L2" }, 20_000);
  const metrics = useMetrics();

  const queue = (l1.data?.results ?? []).filter((c) => OPEN(c.status));
  const fpClosed = (l1.data?.results ?? []).filter((c) => c.verdict_ai === "False Positive" || c.verdict_ai === "Benign");
  const mine = queue.filter((c) => c.assignee === user?.id);

  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader
        title={`Good to see you, ${displayName(user).split(" ")[0]}`}
        subtitle="Tier-1 queue. The AI team has already triaged each case; review its verdict, then work it or escalate."
        actions={<LaunchScenario />}
      />
      <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Open in Tier-1 queue" value={formatNumber(queue.length)} icon={<Inbox className="size-4" />} hint={`${mine.length} assigned to you`} />
        <StatTile label="Alerts in last 24h" value={formatNumber(metrics.data?.alerts.last_24h)} icon={<Siren className="size-4" />} />
        <StatTile
          label="AI flagged as false positive"
          value={formatNumber(fpClosed.length)}
          icon={<Bot className="size-4" />}
          tone="good"
          hint="Noise the agents filtered for you"
        />
        <StatTile
          label="Avg. AI triage time"
          value={metrics.data?.timings.ai_triage_seconds != null ? `${metrics.data.timings.ai_triage_seconds}s` : "-"}
          icon={<Timer className="size-4" />}
          hint="Alert to full agent report"
        />
      </div>

      <div className="mb-5">
        <SocPosture compact />
      </div>

      <Card title="Tier-1 queue" bodyClassName="p-0">
        {l1.isLoading ? <Spinner /> : <CaseTable cases={queue} showTier={false} emptyTitle="Queue is clear. New alerts will appear here automatically." />}
      </Card>

      <Card title="Escalated to Tier-2" className="mt-5" bodyClassName="p-0">
        {escalated.isLoading ? <Spinner /> : <CaseTable cases={(escalated.data?.results ?? []).filter((c) => OPEN(c.status)).slice(0, 8)} showTier={false} emptyTitle="Nothing escalated" />}
      </Card>
    </div>
  );
}
