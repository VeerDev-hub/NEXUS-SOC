"use client";

import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";
import clsx from "clsx";
import { useToasts } from "@/lib/toast";

const ICONS = { info: Info, success: CheckCircle2, warning: AlertTriangle, error: XCircle };

export default function Toaster() {
  const { toasts, dismiss } = useToasts();
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2 no-print">
      {toasts.map((t) => {
        const Icon = ICONS[t.kind];
        return (
          <div
            key={t.id}
            className="pointer-events-auto flex items-start gap-2 rounded-md border border-line-strong bg-panel-2 px-3 py-2 text-sm shadow-xl"
          >
            <Icon
              className={clsx("mt-0.5 size-4 shrink-0", {
                "text-accent": t.kind === "info",
                "text-good": t.kind === "success",
                "text-warning": t.kind === "warning",
                "text-critical": t.kind === "error",
              })}
            />
            <span className="flex-1 text-ink-2">{t.message}</span>
            <button onClick={() => dismiss(t.id)} className="text-ink-3 hover:text-ink" aria-label="Dismiss">
              <X className="size-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
