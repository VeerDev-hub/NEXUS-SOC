"use client";

import Link from "next/link";
import { Loader2 } from "lucide-react";
import { agentMeta } from "@/lib/agents";
import { formatDuration, timeAgo } from "@/lib/format";
import { useRuns } from "@/lib/queries";
import { Empty, ModeBadge, Spinner, VerdictBadge } from "./ui";

export default function RunFeed({ limit = 8 }: { limit?: number }) {
  const q = useRuns();
  if (q.isLoading) return <Spinner />;
  const runs = (q.data?.results ?? []).slice(0, limit);
  if (!runs.length) return <Empty title="No agent runs yet" />;
  return (
    <ul className="divide-y divide-line">
      {runs.map((r) => (
        <li key={r.id}>
          <Link href={`/cases/${r.case_pk}`} className="flex items-center gap-3 px-1 py-2.5 hover:bg-panel-2/60">
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm">{r.case_title}</div>
              <div className="flex items-center gap-2 text-[11px] text-ink-3">
                <span className="font-mono">{r.case_id.toUpperCase()}</span>
                <span>{timeAgo(r.started_at)}</span>
                <span>{r.status === "Running" ? "" : formatDuration(r.duration_ms)}</span>
              </div>
            </div>
            {r.status === "Running" ? (
              <span className="flex items-center gap-1 text-xs text-accent">
                <Loader2 className="size-3.5 animate-spin" />
                {r.current_agent ? agentMeta(r.current_agent).short : "starting"}
              </span>
            ) : (
              <div className="flex items-center gap-2">
                <ModeBadge mode={r.llm_mode} />
                <VerdictBadge value={r.final_verdict || (r.status === "Failed" ? "Failed" : "")} />
              </div>
            )}
          </Link>
        </li>
      ))}
    </ul>
  );
}
