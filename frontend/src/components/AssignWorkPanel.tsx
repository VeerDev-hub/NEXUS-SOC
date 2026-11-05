"use client";

import Link from "next/link";
import { useState } from "react";
import { Bot, UserPlus } from "lucide-react";
import AssigneeSelect from "@/components/AssigneeSelect";
import { Badge, Card, cx, Empty, SeverityBadge, Spinner, Table, VerdictBadge } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { useCases } from "@/lib/queries";
import type { Case } from "@/lib/types";

const OPEN = new Set(["New", "In Progress", "On Hold"]);
const SEVERITY_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };

function severityOf(c: Case) {
  return c.severity_ai || c.severity || "";
}

/** Manager/admin work board: every open case with a teammate dropdown. Unassigned and most severe first. */
export default function AssignWorkPanel({ className }: { className?: string }) {
  const cases = useCases({ page_size: 100 }, 30_000);
  const [view, setView] = useState<"unassigned" | "open">("unassigned");
  const open = (cases.data?.results ?? []).filter((c) => OPEN.has(c.status));
  const unassigned = open.filter((c) => !c.assignee);
  const rows = (view === "unassigned" ? unassigned : open).sort(
    (a, b) =>
      Number(!!a.assignee) - Number(!!b.assignee) ||
      (SEVERITY_ORDER[severityOf(a)] ?? 9) - (SEVERITY_ORDER[severityOf(b)] ?? 9) ||
      b.created_at.localeCompare(a.created_at),
  );

  return (
    <Card
      className={className}
      bodyClassName="p-0"
      title={
        <span className="flex items-center gap-2">
          <UserPlus className="size-4 text-ink-3" /> Assign work
          {unassigned.length > 0 && <Badge tone="warning">{unassigned.length} unassigned</Badge>}
        </span>
      }
      action={
        <div className="flex rounded-md border border-line text-xs">
          {(["unassigned", "open"] as const).map((v) => (
            <button key={v} onClick={() => setView(v)} className={cx("px-2.5 py-1", view === v ? "bg-accent/15 text-ink" : "text-ink-3 hover:text-ink")}>
              {v === "unassigned" ? "Unassigned" : "All open"}
            </button>
          ))}
        </div>
      }
    >
      {cases.isLoading ? (
        <Spinner />
      ) : rows.length ? (
        <>
          <Table head={["Case", "Severity", "AI verdict", "Queue", "Age", "Assign to"]}>
            {rows.slice(0, 25).map((c) => (
              <tr key={c.id} className="hover:bg-panel-2/60">
                <td className="max-w-[420px] px-3 py-2">
                  <Link href={`/cases/${c.id}`} className="block">
                    <span className="font-mono text-[11px] text-ink-3">{c.case_id.toUpperCase()}</span>
                    <div className="truncate font-medium text-ink hover:text-[#8fbcf3]">{c.title}</div>
                  </Link>
                </td>
                <td className="px-3 py-2">
                  <SeverityBadge value={severityOf(c)} />
                </td>
                <td className="px-3 py-2">
                  {c.verdict_ai ? (
                    <span className="flex items-center gap-1">
                      <Bot className="size-3.5 text-ink-3" />
                      <VerdictBadge value={c.verdict_ai} />
                    </span>
                  ) : (
                    <span className="text-xs text-ink-3">pending</span>
                  )}
                </td>
                <td className="px-3 py-2">
                  <Badge tone={c.tier === "L2" ? "serious" : "neutral"}>{c.tier}</Badge>
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-3">{timeAgo(c.created_at)}</td>
                <td className="px-3 py-2">
                  <AssigneeSelect c={c} />
                </td>
              </tr>
            ))}
          </Table>
          <div className="border-t border-line px-3 py-2 text-xs text-ink-3">
            The person you pick gets an inbox message and an email with the case summary and a link.
            {rows.length > 25 && ` Showing 25 of ${rows.length}; see all on the Cases page.`}
          </div>
        </>
      ) : (
        <Empty title={view === "unassigned" ? "Every open case has an owner" : "No open cases"} icon={<UserPlus className="size-7" />} />
      )}
    </Card>
  );
}
