"use client";

import clsx from "clsx";
import { AlertOctagon, AlertTriangle, CheckCircle2, Info, Loader2, ShieldAlert, X } from "lucide-react";
import { useEffect, type ButtonHTMLAttributes, type ReactNode } from "react";

export { clsx as cx };

/* ---------- Button ---------- */
type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "success";

export function Button({
  variant = "secondary",
  size = "md",
  loading,
  icon,
  className,
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: "sm" | "md"; loading?: boolean; icon?: ReactNode }) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={clsx(
        "inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        size === "sm" ? "h-8 px-3 text-xs" : "h-9 px-4 text-sm",
        {
          primary: "bg-accent text-white hover:bg-accent-strong",
          secondary: "border border-line-strong bg-panel-2 text-ink hover:border-ink-3",
          ghost: "text-ink-2 hover:bg-panel-2 hover:text-ink",
          danger: "bg-critical/90 text-white hover:bg-critical",
          success: "bg-good/90 text-white hover:bg-good",
        }[variant],
        className,
      )}
    >
      {loading ? <Loader2 className="size-4 animate-spin" /> : icon}
      {children}
    </button>
  );
}

/* ---------- Card ---------- */
export function Card({ title, action, children, className, bodyClassName }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string }) {
  return (
    <section className={clsx("rounded-lg border border-line bg-panel print-plain", className)}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          {action}
        </header>
      )}
      <div className={clsx("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

/* ---------- Badges ---------- */
export function Badge({ children, className, tone = "neutral" }: { children: ReactNode; className?: string; tone?: "neutral" | "accent" | "good" | "warning" | "serious" | "critical" }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset",
        {
          neutral: "bg-panel-2 text-ink-2 ring-line-strong",
          accent: "bg-accent/12 text-[#8fbcf3] ring-accent/40",
          good: "bg-good/12 text-[#6fd36f] ring-good/40",
          warning: "bg-warning/12 text-warning ring-warning/40",
          serious: "bg-serious/12 text-serious ring-serious/40",
          critical: "bg-critical/15 text-[#f08080] ring-critical/50",
        }[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

const SEVERITY_TONE: Record<string, "critical" | "serious" | "warning" | "good" | "neutral"> = {
  Critical: "critical",
  High: "serious",
  Medium: "warning",
  Low: "good",
};
const SEVERITY_ICON: Record<string, typeof AlertOctagon> = {
  Critical: AlertOctagon,
  High: ShieldAlert,
  Medium: AlertTriangle,
  Low: Info,
};

/** Severity always shows icon + label, never colour alone. */
export function SeverityBadge({ value }: { value?: string | null }) {
  if (!value) return <span className="text-ink-3">-</span>;
  const Icon = SEVERITY_ICON[value] ?? Info;
  return (
    <Badge tone={SEVERITY_TONE[value] ?? "neutral"}>
      <Icon className="size-3" aria-hidden />
      {value}
    </Badge>
  );
}

export function VerdictBadge({ value }: { value?: string | null }) {
  if (!value) return <span className="text-ink-3">-</span>;
  const tone = value === "True Positive" ? "critical" : value === "Suspicious" ? "warning" : value === "False Positive" || value === "Benign" ? "good" : "neutral";
  const Icon = tone === "critical" ? ShieldAlert : tone === "good" ? CheckCircle2 : AlertTriangle;
  return (
    <Badge tone={tone}>
      <Icon className="size-3" aria-hidden />
      {value}
    </Badge>
  );
}

export function StatusBadge({ value }: { value: string }) {
  const tone = value === "New" ? "accent" : value === "In Progress" ? "warning" : value === "Resolved" || value === "Closed" ? "good" : "neutral";
  return <Badge tone={tone}>{value}</Badge>;
}

export function ModeBadge({ mode }: { mode?: string }) {
  if (!mode) return <Badge>policy</Badge>;
  if (mode === "online") return <Badge tone="accent">LLM</Badge>;
  if (mode === "mixed") return <Badge tone="warning">mixed</Badge>;
  return <Badge>offline</Badge>;
}

/* ---------- KPI tile ---------- */
export function StatTile({ label, value, hint, icon, tone }: { label: string; value: ReactNode; hint?: ReactNode; icon?: ReactNode; tone?: "critical" | "warning" | "good" }) {
  return (
    <div className="rounded-lg border border-line bg-panel p-4">
      <div className="flex items-center justify-between text-xs font-medium text-ink-3">
        <span>{label}</span>
        {icon && <span className={clsx(tone === "critical" && "text-critical", tone === "warning" && "text-warning", tone === "good" && "text-good")}>{icon}</span>}
      </div>
      <div className="mt-2 text-2xl font-semibold tracking-tight text-ink tabular-nums">{value}</div>
      {hint && <div className="mt-1 text-xs text-ink-3">{hint}</div>}
    </div>
  );
}

/* ---------- Misc ---------- */
export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-sm text-ink-3">
      <Loader2 className="size-4 animate-spin" /> {label ?? "Loading..."}
    </div>
  );
}

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      {icon && <div className="text-ink-3">{icon}</div>}
      <div className="text-sm font-medium text-ink-2">{title}</div>
      {children && <div className="max-w-md text-xs text-ink-3">{children}</div>}
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  return (
    <div className="rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-sm text-[#f3a5a5]">
      {error instanceof Error ? error.message : "Something went wrong."}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-ink-3">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2 no-print">{actions}</div>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, footer, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className={clsx("w-full rounded-lg border border-line-strong bg-panel shadow-2xl", wide ? "max-w-2xl" : "max-w-md")} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal>
        <div className="flex items-center justify-between border-b border-line px-4 py-3">
          <h3 className="text-sm font-semibold">{title}</h3>
          <button onClick={onClose} className="text-ink-3 hover:text-ink" aria-label="Close">
            <X className="size-4" />
          </button>
        </div>
        <div className="p-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line px-4 py-3">{footer}</div>}
      </div>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { key: T; label: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="flex gap-1 border-b border-line no-print">
      {tabs.map((t) => (
        <button
          key={t.key}
          onClick={() => onChange(t.key)}
          className={clsx(
            "-mb-px border-b-2 px-3 py-2 text-sm transition-colors",
            value === t.key ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2",
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export const inputClass =
  "w-full rounded-md border border-line-strong bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none";

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-ink-2">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-ink-3">{hint}</span>}
    </label>
  );
}

export function Table({ head, children }: { head: ReactNode[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line text-xs text-ink-3">
            {head.map((h, i) => (
              <th key={i} className="whitespace-nowrap px-3 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line">{children}</tbody>
      </table>
    </div>
  );
}
