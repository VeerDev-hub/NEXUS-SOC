"use client";

import Link from "next/link";
import { useState } from "react";
import { Card, cx, inputClass, ModeBadge, PageHeader, Spinner, Table, VerdictBadge } from "@/components/ui";
import { formatDateTime, formatDuration } from "@/lib/format";
import { useRuns } from "@/lib/queries";

export default function DecisionTrail() {
  const [status, setStatus] = useState("");
  const [mode, setMode] = useState("");
  const q = useRuns({ status, llm_mode: mode });
  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader
        title="Decision trail"
        subtitle="Every agent run is recorded step by step: who triggered it, how the Supervisor routed it, which tools ran and what was decided."
      />
      <Card bodyClassName="p-0">
        <div className="flex flex-wrap gap-2 border-b border-line p-3">
          <select className={cx(inputClass, "w-auto")} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Any status</option>
            <option>Running</option>
            <option>Completed</option>
            <option>Failed</option>
          </select>
          <select className={cx(inputClass, "w-auto")} value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="">Any LLM mode</option>
            <option value="online">Online LLM</option>
            <option value="offline">Offline engine</option>
            <option value="mixed">Mixed</option>
          </select>
        </div>
        {q.isLoading ? (
          <Spinner />
        ) : (
          <Table head={["Started", "Case", "Trigger", "Mode", "Outcome", "Confidence", "Duration", "Tokens"]}>
            {(q.data?.results ?? []).map((r) => (
              <tr key={r.id} className="hover:bg-panel-2/60">
                <td className="whitespace-nowrap px-3 py-2.5 text-xs text-ink-3">{formatDateTime(r.started_at)}</td>
                <td className="max-w-[380px] px-3 py-2.5">
                  <Link href={`/cases/${r.case_pk}`} className="block truncate hover:text-[#8fbcf3]">
                    <span className="mr-2 font-mono text-[11px] text-ink-3">{r.case_id.toUpperCase()}</span>
                    {r.case_title}
                  </Link>
                </td>
                <td className="whitespace-nowrap px-3 py-2.5 text-xs text-ink-2">
                  {r.trigger}
                  {r.triggered_by && <span className="text-ink-3"> · {r.triggered_by.name}</span>}
                </td>
                <td className="px-3 py-2.5">
                  <ModeBadge mode={r.llm_mode} />
                </td>
                <td className="px-3 py-2.5">{r.status === "Completed" ? <VerdictBadge value={r.final_verdict} /> : <span className="text-xs text-ink-3">{r.status}</span>}</td>
                <td className="px-3 py-2.5 tabular-nums text-xs">{r.final_confidence != null ? `${r.final_confidence}%` : "-"}</td>
                <td className="px-3 py-2.5 tabular-nums text-xs">{formatDuration(r.duration_ms)}</td>
                <td className="px-3 py-2.5 tabular-nums text-xs">{r.total_tokens}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
