"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Plus, Save, Trash2 } from "lucide-react";
import { RequirePermission } from "@/components/AppShell";
import { Badge, Button, Card, cx, Field, inputClass, Modal, PageHeader, Spinner, Table } from "@/components/ui";
import { del, get, patch, post } from "@/lib/api";
import { toast } from "@/lib/toast";
import type { Paginated } from "@/lib/types";

interface Runtime {
  agent_llm_mode: "auto" | "online" | "offline";
  agent_max_steps: number;
  agent_auto_run: boolean;
}

interface Provider {
  id: string;
  name: string;
  provider: "deepseek" | "openai" | "gemini" | "openai_compatible";
  base_url: string;
  model: string;
  api_key_configured: boolean;
  tags: string[];
  enabled: boolean;
  priority: number;
}

const PROVIDERS = {
  deepseek: { label: "DeepSeek", base_url: "https://api.deepseek.com", model: "deepseek-chat" },
  openai: { label: "OpenAI", base_url: "https://api.openai.com/v1", model: "gpt-4.1-mini" },
  gemini: { label: "Google Gemini", base_url: "https://generativelanguage.googleapis.com/v1beta/openai/", model: "gemini-2.5-flash" },
  openai_compatible: { label: "OpenAI-compatible (Ollama, vLLM...)", base_url: "http://localhost:11434/v1", model: "" },
} as const;

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

function ProviderModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<{ provider: Provider["provider"]; name: string; base_url: string; model: string; api_key: string; tags: string; priority: number }>({ provider: "deepseek", name: "DeepSeek", base_url: PROVIDERS.deepseek.base_url, model: PROVIDERS.deepseek.model, api_key: "", tags: "", priority: 10 });
  const create = useMutation({
    mutationFn: () => post("/settings/llm-providers", { ...form, tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean), enabled: true }),
    onSuccess: () => {
      toast("Provider added", "success");
      qc.invalidateQueries({ queryKey: ["providers"] });
      qc.invalidateQueries({ queryKey: ["llm-status"] });
      onClose();
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add LLM provider"
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} onClick={() => create.mutate()} disabled={!form.name || !form.model}>
            Add provider
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <Field label="Provider">
          <select
            className={inputClass}
            value={form.provider}
            onChange={(e) => {
              const key = e.target.value as Provider["provider"];
              setForm({ ...form, provider: key, name: PROVIDERS[key].label.split(" (")[0], base_url: PROVIDERS[key].base_url, model: PROVIDERS[key].model });
            }}
          >
            {Object.entries(PROVIDERS).map(([k, v]) => (
              <option key={k} value={k}>
                {v.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Display name">
          <input className={inputClass} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </Field>
        <Field label="Base URL">
          <input className={inputClass} value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })} />
        </Field>
        <Field label="Model">
          <input className={inputClass} value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} />
        </Field>
        <Field label="API key">
          <input type="password" className={inputClass} value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} />
        </Field>
        <Field label="Priority" hint="Lowest number is the primary model.">
          <input type="number" className={inputClass} value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} />
        </Field>
        <div className="col-span-2">
          <Field label="Agent tags (optional)" hint="Route specific agents to this model, e.g. agent:investigation, agent:reporting. Untagged agents use the primary model.">
            <input className={inputClass} value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
          </Field>
        </div>
      </div>
    </Modal>
  );
}

function Settings() {
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["providers"], queryFn: () => get<Paginated<Provider> | Provider[]>("/settings/llm-providers") });
  const [open, setOpen] = useState(false);
  const list = Array.isArray(providers.data) ? providers.data : providers.data?.results ?? [];
  const toggle = useMutation({
    mutationFn: (p: Provider) => patch(`/settings/llm-providers/${p.id}`, { enabled: !p.enabled }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providers"] });
      qc.invalidateQueries({ queryKey: ["llm-status"] });
    },
  });
  const remove = useMutation({
    mutationFn: (p: Provider) => del(`/settings/llm-providers/${p.id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providers"] });
      qc.invalidateQueries({ queryKey: ["llm-status"] });
    },
  });

  return (
    <div className="mx-auto max-w-[1100px] space-y-5">
      <PageHeader title="Platform settings" subtitle="Choose how the agents think: which LLM, and what happens when it is not available." />
      <RuntimeCard />
      <Card
        title="LLM providers"
        action={
          <Button size="sm" variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setOpen(true)}>
            Add provider
          </Button>
        }
        bodyClassName="p-0"
      >
        {providers.isLoading ? (
          <Spinner />
        ) : list.length ? (
          <Table head={["Name", "Provider", "Model", "Key", "Tags", "Priority", "Enabled", ""]}>
            {list.map((p) => (
              <tr key={p.id}>
                <td className="px-3 py-2.5 font-medium">{p.name}</td>
                <td className="px-3 py-2.5 text-xs text-ink-2">{PROVIDERS[p.provider]?.label ?? p.provider}</td>
                <td className="px-3 py-2.5 font-mono text-xs">{p.model}</td>
                <td className="px-3 py-2.5">{p.api_key_configured ? <Badge tone="good">set</Badge> : <Badge tone="warning">missing</Badge>}</td>
                <td className="px-3 py-2.5 text-xs text-ink-3">{p.tags.join(", ") || "-"}</td>
                <td className="px-3 py-2.5 tabular-nums">{p.priority}</td>
                <td className="px-3 py-2.5">
                  <button onClick={() => toggle.mutate(p)}>
                    <Badge tone={p.enabled ? "good" : "neutral"}>{p.enabled ? "On" : "Off"}</Badge>
                  </button>
                </td>
                <td className="px-3 py-2.5 text-right">
                  <button onClick={() => confirm(`Remove ${p.name}?`) && remove.mutate(p)} className="text-ink-3 hover:text-critical" title="Remove">
                    <Trash2 className="size-4" />
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <div className="p-4 text-sm text-ink-3">
            No provider configured. The agents run on the offline engine. Add DeepSeek, OpenAI or Gemini to enable LLM reasoning, or set
            <code className="mx-1">DEEPSEEK_API_KEY</code> in the backend <code>.env</code>.
          </div>
        )}
      </Card>
      <ProviderModal open={open} onClose={() => setOpen(false)} />
    </div>
  );
}
