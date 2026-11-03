"use client";

import Link from "next/link";
import { Bot, Loader2 } from "lucide-react";
import { useRuns } from "@/lib/queries";
import { timeAgo } from "@/lib/format";
import type { Case } from "@/lib/types";
import { Badge, Empty, SeverityBadge, StatusBadge, Table, VerdictBadge } from "./ui";

export default function CaseTable({ cases, emptyTitle = "No cases", showTier = true }: { cases: Case[]; emptyTitle?: string; showTier?: boolean }) {
  const running = useRuns({ status: "Running" });
  const runningCases = new Set((running.data?.results ?? []).map((r) => r.case_pk));

  if (!cases.length) return <Empty title={emptyTitle} />;
  return (
    <Table head={["Case", "Severity", "AI verdict", "Status", ...(showTier ? ["Queue"] : []), "Assignee", "Updated"]}>
      {cases.map((c) => (
        <tr key={c.id} className="hover:bg-panel-2/60">
          <td className="max-w-[460px] px-3 py-2.5">
            <Link href={`/cases/${c.id}`} className="block">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[11px] text-ink-3">{c.case_id.toUpperCase()}</span>
                {runningCases.has(c.id) && (
                  <span className="flex items-center gap-1 text-[11px] text-accent">
                    <Loader2 className="size-3 animate-spin" /> agents working
                  </span>
                )}
              </div>
              <div className="truncate font-medium text-ink hover:text-[#8fbcf3]">{c.title}</div>
            </Link>
          </td>
          <td className="px-3 py-2.5">
            <SeverityBadge value={c.severity_ai || c.severity} />
          </td>
          <td className="px-3 py-2.5">
            {c.verdict_ai ? (
              <span className="flex items-center gap-1">
                <Bot className="size-3.5 text-ink-3" />
                <VerdictBadge value={c.verdict_ai} />
              </span>
            ) : (
              <span className="text-xs text-ink-3">pending</span>
            )}
          </td>
          <td className="px-3 py-2.5">
            <StatusBadge value={c.status} />
          </td>
          {showTier && (
            <td className="px-3 py-2.5">
              <Badge tone={c.tier === "L2" ? "serious" : "neutral"}>{c.tier}</Badge>
            </td>
          )}
          <td className="whitespace-nowrap px-3 py-2.5 text-xs text-ink-2">{c.assignee_name || <span className="text-ink-3">unassigned</span>}</td>
          <td className="whitespace-nowrap px-3 py-2.5 text-xs text-ink-3">{timeAgo(c.updated_at)}</td>
        </tr>
      ))}
    </Table>
  );
}
