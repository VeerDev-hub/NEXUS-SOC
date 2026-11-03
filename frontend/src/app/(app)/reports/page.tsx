"use client";

import Link from "next/link";
import { FileText } from "lucide-react";
import { Card, Empty, PageHeader, SeverityBadge, Spinner, VerdictBadge } from "@/components/ui";
import { formatDateTime } from "@/lib/format";
import { useRuns } from "@/lib/queries";

export default function ReportsPage() {
  const q = useRuns({ status: "Completed" });
  // Latest completed run per case.
  const seen = new Set<string>();
  const reports = (q.data?.results ?? []).filter((r) => (seen.has(r.case_pk) ? false : (seen.add(r.case_pk), true)));

  return (
    <div className="mx-auto max-w-[1100px]">
      <PageHeader title="Incident reports" subtitle="Final reports written by the Reporting Agent. Open one to read or export it as PDF." />
      {q.isLoading ? (
        <Spinner />
      ) : reports.length ? (
        <div className="grid gap-3 md:grid-cols-2">
          {reports.map((r) => (
            <Link key={r.id} href={`/reports/${r.id}`}>
              <Card className="h-full transition-colors hover:border-line-strong">
                <div className="flex items-center gap-2 text-xs text-ink-3">
                  <FileText className="size-3.5" />
                  <span className="font-mono">{r.case_id.toUpperCase()}</span>
                  <span>· {formatDateTime(r.completed_at)}</span>
                </div>
                <div className="mt-1 font-medium">{r.case_title}</div>
                <div className="mt-2 flex gap-2">
                  <VerdictBadge value={r.final_verdict} />
                  <SeverityBadge value={r.final_severity} />
                </div>
                <p className="mt-2 line-clamp-3 text-xs text-ink-3">{r.summary}</p>
              </Card>
            </Link>
          ))}
        </div>
      ) : (
        <Empty title="No reports yet" icon={<FileText className="size-8" />}>
          Reports appear once the agent team finishes a case.
        </Empty>
      )}
    </div>
  );
}
