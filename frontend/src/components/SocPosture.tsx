"use client";

import { CasesTrendChart, HorizontalBars, ResolutionTrendChart, SeverityBreakdown, SeverityLegend, TacticHeatmap } from "./charts";
import { Card, Spinner } from "./ui";
import { useMetrics } from "@/lib/queries";

/**
 * The shared "main picture" every role sees on its home page:
 * case volume by severity over two weeks, what is open right now, where cases sit in the
 * workflow, where alerts come from, which ATT&CK tactics are active and how fast we resolve.
 */
export default function SocPosture({ compact = false }: { compact?: boolean }) {
  const m = useMetrics();
  if (m.isLoading || !m.data) return <Spinner label="Loading SOC posture..." />;
  const c = m.data.charts;
  const totals = c.cases_daily.reduce((n, d) => n + d.total, 0);

  return (
    <div className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card
          title={
            <span>
              Cases opened per day by severity <span className="font-normal text-ink-3">· last 14 days · {totals} cases</span>
            </span>
          }
          action={<SeverityLegend />}
          className="flex flex-col"
          bodyClassName="flex-1 min-h-[300px]"
        >
          {/* Fills the card so it lines up with the right-hand column. */}
          <CasesTrendChart data={c.cases_daily} />
        </Card>
        <div className="grid gap-5">
          <Card title={`Open now by severity · ${m.data.cases.open}`}>
            <SeverityBreakdown data={c.open_by_severity} />
          </Card>
          <Card title="Case pipeline">
            <HorizontalBars data={c.pipeline.map((p) => ({ label: p.status, value: p.count }))} unit="Cases" labelWidth={84} height={150} />
          </Card>
        </div>
      </div>

      {!compact && (
        <div className="grid gap-5 lg:grid-cols-2 2xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)]">
          <Card title="MITRE ATT&CK tactics × severity (alerts)">
            <TacticHeatmap data={c.tactic_heatmap} />
          </Card>
          <Card title="Alerts by source">
            <HorizontalBars data={c.alert_sources.map((s) => ({ label: s.source, value: s.count }))} unit="Alerts" labelWidth={90} />
          </Card>
          <Card title="Mean time to resolve (hours) · 14 days">
            <ResolutionTrendChart data={c.resolution_daily} />
          </Card>
        </div>
      )}
    </div>
  );
}
