"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Save } from "lucide-react";
import LLMProvidersPanel from "@/components/agents/LLMProvidersPanel";
import { RequirePermission } from "@/components/AppShell";
import { Button, Card, cx, Field, inputClass, PageHeader, Spinner } from "@/components/ui";
import { get, patch } from "@/lib/api";
import { toast } from "@/lib/toast";

interface Runtime {
  agent_llm_mode: "auto" | "online" | "offline";
  agent_max_steps: number;
  agent_auto_run: boolean;
}

const MODES = [
  { value: "auto", label: "Auto", hint: "Use the LLM; fall back to the offline engine if it is unreachable or fails." },
  { value: "online", label: "Online only", hint: "Always use the LLM; errors stop the run." },
  { value: "offline", label: "Offline engine", hint: "Never call an LLM. Rule-based agents only (demo without internet)." },
] as const;

export default function SettingsPage() {
  return (
    <RequirePermission perm="settings.manage">
      <Settings />
    </RequirePermission>
  );
}

function RuntimeCard() {
  const q = useQuery({ queryKey: ["runtime"], queryFn: () => get<Runtime>("/settings/runtime") });
  if (!q.data) return <Spinner />;
  return <RuntimeForm key={q.dataUpdatedAt} initial={q.data} />;
}

function RuntimeForm({ initial }: { initial: Runtime }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<Runtime>(initial);
  const save = useMutation({
    mutationFn: () => patch<Runtime>("/settings/runtime", form),
    onSuccess: () => {
      toast("Agent runtime saved", "success");
      qc.invalidateQueries({ queryKey: ["runtime"] });
      qc.invalidateQueries({ queryKey: ["llm-status"] });
      qc.invalidateQueries({ queryKey: ["agent-catalog"] });
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  return (
    <Card
      title="Agent runtime"
      action={
        <Button size="sm" variant="primary" icon={<Save className="size-3.5" />} loading={save.isPending} onClick={() => save.mutate()}>
          Save
        </Button>
      }
    >
      <div className="grid gap-3 md:grid-cols-3">
        {MODES.map((m) => (
          <button
            key={m.value}
            onClick={() => setForm({ ...form, agent_llm_mode: m.value })}
            className={cx("rounded-md border p-3 text-left", form.agent_llm_mode === m.value ? "border-accent bg-accent/10" : "border-line hover:border-line-strong")}
          >
            <div className="text-sm font-medium">{m.label}</div>
            <div className="mt-1 text-xs text-ink-3">{m.hint}</div>
          </button>
        ))}
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Field label="Max agent steps per run" hint="Supervisor forces the report before this budget runs out.">
          <input type="number" min={4} max={20} className={inputClass} value={form.agent_max_steps} onChange={(e) => setForm({ ...form, agent_max_steps: Number(e.target.value) })} />
        </Field>
        <label className="flex items-center gap-2 pt-6 text-sm">
          <input type="checkbox" checked={form.agent_auto_run} onChange={(e) => setForm({ ...form, agent_auto_run: e.target.checked })} />
          Run the agent team automatically on every new alert
        </label>
      </div>
    </Card>
  );
}

function Settings() {
  return (
    <div className="mx-auto max-w-[1100px] space-y-5">
      <PageHeader title="Platform settings" subtitle="Choose how the agents think: which LLM, and what happens when it is not available." />
      <RuntimeCard />
      <LLMProvidersPanel />
    </div>
  );
}
