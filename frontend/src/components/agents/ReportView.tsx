"use client";

import { Badge, Card, Empty, SeverityBadge, Table, VerdictBadge } from "../ui";
import type { FinalReport } from "@/lib/types";

export default function ReportView({ report, title, meta }: { report?: Partial<FinalReport> | null; title?: string; meta?: React.ReactNode }) {
  if (!report || !report.verdict) {
    return <Empty title="No report yet">The Reporting Agent writes the final report at the end of an agent run.</Empty>;
  }
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-line bg-panel p-5 print-plain">
        {title && <h2 className="text-lg font-semibold">{title}</h2>}
        {meta && <div className="mt-1 text-xs text-ink-3">{meta}</div>}
        <div className="mt-3 flex flex-wrap gap-2">
          <VerdictBadge value={report.verdict} />
          <SeverityBadge value={report.severity} />
          <Badge>Impact: {report.impact}</Badge>
          <Badge>Priority: {report.priority}</Badge>
          <Badge tone="accent">Confidence: {report.confidence}</Badge>
        </div>
        <h3 className="mt-5 text-xs font-semibold uppercase tracking-wide text-ink-3">Executive summary</h3>
        <p className="mt-1 text-sm leading-relaxed text-ink">{report.executive_summary}</p>
        <p className="mt-3 font-mono text-xs text-ink-3">{report.digest}</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Attack chain (MITRE ATT&CK)">
          {report.attack_chain?.length ? (
            <ol className="space-y-2">
              {report.attack_chain.map((s, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-accent/20 text-[11px] font-semibold text-[#8fbcf3]">{i + 1}</span>
                  <div>
                    <div className="font-medium">{s.attack_stage}</div>
                    <div className="text-xs text-ink-3">{s.description}</div>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <span className="text-sm text-ink-3">No mapped stages.</span>
          )}
        </Card>
        <Card title="Affected assets">
          <div className="flex flex-wrap gap-2">
            {(report.affected_assets ?? []).map((a) => (
              <span key={a.asset_value} className="rounded border border-line-strong bg-bg px-2 py-1 text-xs">
                <span className="text-ink-3">{a.asset_type}:</span> <code>{a.asset_value}</code>
              </span>
            ))}
            {!report.affected_assets?.length && <span className="text-sm text-ink-3">None identified.</span>}
          </div>
        </Card>
      </div>

      <Card title="Timeline" bodyClassName="p-0">
        <Table head={["Time", "Behaviour", "Evidence"]}>
          {(report.attack_timeline ?? []).map((t, i) => (
            <tr key={i}>
              <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-ink-3">{t.timestamp ? new Date(t.timestamp).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) : "-"}</td>
              <td className="px-3 py-2">{t.attack_behavior}</td>
              <td className="px-3 py-2 font-mono text-xs text-ink-3">{t.evidence_field}</td>
            </tr>
          ))}
        </Table>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Indicators of compromise" bodyClassName="p-0">
          {report.ioc_indicators?.length ? (
            <Table head={["Type", "Value", "Context"]}>
              {report.ioc_indicators.map((i) => (
                <tr key={i.value}>
                  <td className="px-3 py-2 text-xs text-ink-3">{i.indicator_type}</td>
                  <td className="px-3 py-2 font-mono text-xs">{i.value}</td>
                  <td className="px-3 py-2 text-xs text-ink-3">{i.context}</td>
                </tr>
              ))}
            </Table>
          ) : (
            <div className="p-4 text-sm text-ink-3">No malicious or suspicious indicators.</div>
          )}
        </Card>
        <Card title="Remediation">
          <ul className="space-y-2">
            {(report.remediations ?? []).map((r, i) => (
              <li key={i} className="text-sm">
                <code className="text-[#8fbcf3]">{r.action_type}</code>
                <span className="text-ink-2"> - {r.description}</span>
              </li>
            ))}
            {!report.remediations?.length && <li className="text-sm text-ink-3">No actions required.</li>}
          </ul>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Evidence">
          <ul className="space-y-3">
            {(report.evidence_findings ?? []).map((f, i) => (
              <li key={i} className="text-sm">
                <div className="font-medium">{f.title}</div>
                <div className="text-xs text-ink-3">{f.evidence}</div>
                <div className="text-xs text-ink-2">{f.conclusion}</div>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Open questions">
          <ul className="ml-4 list-disc space-y-1 text-sm text-ink-2">
            {(report.unknowns ?? []).map((u, i) => (
              <li key={i}>{u}</li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
