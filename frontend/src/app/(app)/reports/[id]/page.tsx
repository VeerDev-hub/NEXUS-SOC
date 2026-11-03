"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, Printer } from "lucide-react";
import ReportView from "@/components/agents/ReportView";
import { Button, ErrorBox, Spinner } from "@/components/ui";
import { formatDateTime } from "@/lib/format";
import { useRun } from "@/lib/queries";

export default function ReportDetail() {
  const { id } = useParams<{ id: string }>();
  const q = useRun(id);
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorBox error={q.error} />;
  const run = q.data!;
  const agents = (run.steps ?? []).filter((s) => s.agent !== "supervisor").map((s) => s.agent);
  return (
    <div className="mx-auto max-w-[1100px]">
      <div className="mb-4 flex items-center justify-between no-print">
        <Link href="/reports" className="inline-flex items-center gap-1 text-xs text-ink-3 hover:text-ink">
          <ArrowLeft className="size-3.5" /> Reports
        </Link>
        <div className="flex gap-2">
          <Link href={`/cases/${run.case_pk}`}>
            <Button size="sm">Open case</Button>
          </Link>
          <Button size="sm" variant="primary" icon={<Printer className="size-3.5" />} onClick={() => window.print()}>
            Export PDF
          </Button>
        </div>
      </div>
      <ReportView
        report={run.report}
        title={`${run.case_id.toUpperCase()} · ${run.case_title}`}
        meta={`Generated ${formatDateTime(run.completed_at)} by the agent team (${agents.join(" → ")}) · LLM mode: ${run.llm_mode}`}
      />
    </div>
  );
}
