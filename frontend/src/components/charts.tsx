"use client";

/*
 * Chart conventions (data-viz method):
 * - single-series charts use one hue (series-1); the card title names the series, no legend box
 * - severity is ORDINAL, so it uses one validated red ramp (Low dim -> Critical bright on the dark
 *   surface; passed the ordinal checks) plus a legend/axis label - never colour alone
 * - magnitude (heatmap) uses the blue sequential ramp; near-zero recedes toward the surface
 * - thin marks, 4px rounded data ends, 2px surface gaps between stacked segments, recessive grid,
 *   hover tooltip on every mark, one y-axis only
 */
import type { ReactNode } from "react";
import { AlertOctagon, AlertTriangle, Info, ShieldAlert } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const AXIS = { stroke: "#7d8593", fontSize: 11, tickLine: false, axisLine: false } as const;
const GRID = "#262b33";
const SURFACE = "#14171c";
const SERIES_1 = "#3987e5";

export const SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"] as const;
export const SEVERITY_RAMP: Record<string, string> = { Low: "#8a3532", Medium: "#b3443f", High: "#dc5650", Critical: "#ff8077" };
const SEVERITY_ICON = { Low: Info, Medium: AlertTriangle, High: ShieldAlert, Critical: AlertOctagon };
const BLUE_SEQ = ["#1b1f26", "#104281", "#1c5cab", "#2a78d6", "#5598e7", "#86b6ef"];

const IST = "Asia/Kolkata";
const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString("en-IN", { timeZone: IST, hour: "2-digit", minute: "2-digit", hour12: false });
const dayLabel = (iso: string) => new Date(`${iso}T00:00:00`).toLocaleDateString("en-IN", { day: "2-digit", month: "short" });

/* ------------------------------------------------------------------ tooltip */
function TooltipBox({ title, rows }: { title: ReactNode; rows: { label: ReactNode; value: ReactNode; swatch?: string }[] }) {
  return (
    <div className="min-w-[140px] rounded-md border border-line-strong bg-panel-2 px-2.5 py-1.5 text-xs shadow-lg">
      <div className="mb-1 text-ink-3">{title}</div>
      {rows.map((r, i) => (
        <div key={i} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 text-ink-2">
            {r.swatch && <span className="size-2 rounded-sm" style={{ background: r.swatch }} />}
            {r.label}
          </span>
          <span className="font-semibold text-ink tabular-nums">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

function SimpleTooltip({ active, payload, label, unit, labelFormatter }: {
  active?: boolean;
  payload?: { value: number }[];
  label?: string;
  unit: string;
  labelFormatter?: (l: string) => string;
}) {
  if (!active || !payload?.length) return null;
  return <TooltipBox title={labelFormatter ? labelFormatter(String(label)) : label} rows={[{ label: unit, value: payload[0].value ?? "-" }]} />;
}

export function SeverityLegend() {
  return (
    <div className="flex flex-wrap items-center gap-3 text-[11px] text-ink-2">
      {[...SEVERITY_ORDER].reverse().map((s) => {
        const Icon = SEVERITY_ICON[s];
        return (
          <span key={s} className="flex items-center gap-1">
            <span className="size-2.5 rounded-sm" style={{ background: SEVERITY_RAMP[s] }} />
            <Icon className="size-3 text-ink-3" aria-hidden />
            {s}
          </span>
        );
      })}
    </div>
  );
}

/* --------------------------------------------- main chart: cases per day by severity */
type DailyRow = { day: string; Critical: number; High: number; Medium: number; Low: number; total: number };

export function CasesTrendChart({ data, height = "100%" }: { data: DailyRow[]; height?: number | `${number}%` }) {
  return (
    <ResponsiveContainer width="100%" height={height} minHeight={260}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }} barCategoryGap="22%">
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey="day" tickFormatter={dayLabel} {...AXIS} interval={1} />
        <YAxis allowDecimals={false} {...AXIS} />
        <Tooltip
          cursor={{ fill: "#1b1f26" }}
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TooltipBox
                title={dayLabel(String(label))}
                rows={[
                  ...[...SEVERITY_ORDER].reverse().map((s) => ({ label: s, value: (payload[0].payload as DailyRow)[s], swatch: SEVERITY_RAMP[s] })),
                  { label: <b>Total cases</b>, value: (payload[0].payload as DailyRow).total },
                ]}
              />
            ) : null
          }
        />
        {SEVERITY_ORDER.map((s, i) => (
          <Bar
            key={s}
            dataKey={s}
            stackId="sev"
            fill={SEVERITY_RAMP[s]}
            stroke={SURFACE}
            strokeWidth={2}
            maxBarSize={30}
            radius={i === SEVERITY_ORDER.length - 1 ? [4, 4, 0, 0] : 0}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

/* ------------------------------------------------ open cases by severity (direct labels) */
export function SeverityBreakdown({ data }: { data: { severity: string; count: number }[] }) {
  const max = Math.max(1, ...data.map((d) => d.count));
  const rows = [...data].sort((a, b) => SEVERITY_ORDER.indexOf(b.severity as never) - SEVERITY_ORDER.indexOf(a.severity as never));
  return (
    <ul className="space-y-2.5">
      {rows.map((d) => {
        const Icon = SEVERITY_ICON[d.severity as keyof typeof SEVERITY_ICON] ?? Info;
        return (
          <li key={d.severity} className="group" title={`${d.count} open ${d.severity} case(s)`}>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-ink-2">
                <Icon className="size-3.5 text-ink-3" aria-hidden /> {d.severity}
              </span>
              <span className="font-semibold tabular-nums text-ink">{d.count}</span>
            </div>
            <div className="h-2 rounded bg-panel-2">
              <div className="h-2 rounded transition-all group-hover:brightness-110" style={{ width: `${(d.count / max) * 100}%`, background: SEVERITY_RAMP[d.severity] }} />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/* ---------------------------------------------------------------- MITRE tactic heatmap */
type HeatRow = { tactic: string; Critical: number; High: number; Medium: number; Low: number };

export function TacticHeatmap({ data }: { data: HeatRow[] }) {
  const max = Math.max(1, ...data.flatMap((r) => SEVERITY_ORDER.map((s) => r[s])));
  // 0 -> surface; otherwise one of the 5 blue steps, scaled to the busiest cell.
  const step = (v: number) => (v === 0 ? 0 : 1 + Math.min(4, Math.floor((v / max) * 5 - 1e-9)));
  const cols = [...SEVERITY_ORDER].reverse();
  if (!data.length) return <div className="py-8 text-center text-sm text-ink-3">No ATT&CK-mapped alerts yet.</div>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-separate border-spacing-[2px] text-xs">
        <thead>
          <tr>
            <th className="px-2 py-1 text-left font-medium text-ink-3">Tactic</th>
            {cols.map((s) => (
              <th key={s} className="px-2 py-1 font-medium text-ink-3">
                {s}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((r) => (
            <tr key={r.tactic}>
              <td className="whitespace-nowrap px-2 py-1.5 text-ink-2">{r.tactic}</td>
              {cols.map((s) => {
                const v = r[s];
                const idx = step(v);
                return (
                  <td
                    key={s}
                    title={`${r.tactic} · ${s}: ${v} alert(s)`}
                    className="h-8 min-w-14 rounded text-center tabular-nums transition hover:ring-2 hover:ring-ink-3"
                    style={{ background: BLUE_SEQ[idx], color: idx >= 4 ? "#0b0d11" : v ? "#eceef2" : "#4b525e" }}
                  >
                    {v || "·"}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-2 flex items-center justify-end gap-1 text-[11px] text-ink-3">
        fewer
        {BLUE_SEQ.slice(1).map((c) => (
          <span key={c} className="h-2 w-5 rounded-sm" style={{ background: c }} />
        ))}
        more alerts
      </div>
    </div>
  );
}

/* ------------------------------------------------------- simple single-series charts */
export function AlertTrendChart({ data }: { data: { hour: string; alerts: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={SERIES_1} stopOpacity={0.35} />
            <stop offset="100%" stopColor={SERIES_1} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey="hour" tickFormatter={hourLabel} {...AXIS} interval={3} />
        <YAxis allowDecimals={false} {...AXIS} />
        <Tooltip cursor={{ stroke: "#7d8593", strokeDasharray: "3 3" }} content={<SimpleTooltip unit="Alerts" labelFormatter={hourLabel} />} />
        <Area type="monotone" dataKey="alerts" stroke={SERIES_1} strokeWidth={2} fill="url(#trendFill)" activeDot={{ r: 4, stroke: SURFACE, strokeWidth: 2 }} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function ResolutionTrendChart({ data }: { data: { day: string; closed: number; mttr_hours: number | null }[] }) {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey="day" tickFormatter={dayLabel} {...AXIS} interval={2} />
        <YAxis {...AXIS} unit="h" />
        <Tooltip
          cursor={{ stroke: "#7d8593", strokeDasharray: "3 3" }}
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TooltipBox
                title={dayLabel(String(label))}
                rows={[
                  { label: "Mean time to resolve", value: payload[0].value != null ? `${payload[0].value} h` : "-" },
                  { label: "Cases closed", value: (payload[0].payload as { closed: number }).closed },
                ]}
              />
            ) : null
          }
        />
        <Line type="monotone" dataKey="mttr_hours" stroke={SERIES_1} strokeWidth={2} connectNulls dot={{ r: 4, stroke: SURFACE, strokeWidth: 2, fill: SERIES_1 }} activeDot={{ r: 5 }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

/** Horizontal single-hue bars, e.g. workload per analyst, latency per agent, alerts per source. */
export function HorizontalBars({ data, unit, height, labelWidth = 120 }: { data: { label: string; value: number }[]; unit: string; height?: number; labelWidth?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height ?? Math.max(120, data.length * 34)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }} barCategoryGap="28%">
        <CartesianGrid horizontal={false} stroke={GRID} />
        <XAxis type="number" allowDecimals={false} {...AXIS} />
        <YAxis type="category" dataKey="label" width={labelWidth} {...AXIS} stroke="#b4bac5" />
        <Tooltip cursor={{ fill: "#1b1f26" }} content={<SimpleTooltip unit={unit} />} />
        <Bar dataKey="value" fill={SERIES_1} radius={[0, 4, 4, 0]} maxBarSize={18} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function SeverityBarChart({ data }: { data: { severity: string; count: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }} barCategoryGap="30%">
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey="severity" {...AXIS} />
        <YAxis allowDecimals={false} {...AXIS} />
        <Tooltip cursor={{ fill: "#1b1f26" }} content={<SimpleTooltip unit="Open cases" />} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={44}>
          {data.map((d) => (
            <Cell key={d.severity} fill={SEVERITY_RAMP[d.severity] ?? SERIES_1} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
