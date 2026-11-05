"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ArrowDown, ArrowUp, FlaskConical, Pencil, Plus, Trash2 } from "lucide-react";
import { Badge, Button, Card, Field, inputClass, Modal, Spinner, Table } from "@/components/ui";
import { del, get, patch, post } from "@/lib/api";
import { toast } from "@/lib/toast";
import type { Paginated } from "@/lib/types";

export interface Provider {
  id: string;
  name: string;
  provider: "deepseek" | "openai" | "gemini" | "openrouter" | "ollama" | "openai_compatible";
  base_url: string;
  model: string;
  api_key_configured: boolean;
  tags: string[];
  enabled: boolean;
  priority: number;
}

export const PROVIDERS = {
  deepseek: { label: "DeepSeek", base_url: "https://api.deepseek.com", model: "deepseek-chat" },
  openai: { label: "OpenAI", base_url: "https://api.openai.com/v1", model: "gpt-4.1-mini" },
  gemini: { label: "Google Gemini", base_url: "https://generativelanguage.googleapis.com/v1beta/openai/", model: "gemini-2.5-flash" },
  openrouter: { label: "OpenRouter", base_url: "https://openrouter.ai/api/v1", model: "" },
  ollama: { label: "Ollama (local)", base_url: "http://localhost:11434/v1", model: "qwen2.5-soc:7b-16k" },
  openai_compatible: { label: "OpenAI-compatible (vLLM, OpenRouter...)", base_url: "http://localhost:11434/v1", model: "" },
} as const;

type TestResult = { success: boolean; detail: string; response_preview?: string };

interface FormState {
  provider: Provider["provider"];
  name: string;
  base_url: string;
  model: string;
  api_key: string;
  tags: string;
  priority: number;
}

function useInvalidate() {
  const qc = useQueryClient();
  return () => {
    qc.invalidateQueries({ queryKey: ["providers"] });
    qc.invalidateQueries({ queryKey: ["llm-status"] });
    qc.invalidateQueries({ queryKey: ["agent-catalog"] });
  };
}

/** Add a provider (editing = null) or edit an existing one. A blank API key on edit keeps the stored key. */
function ProviderModal({ editing, nextPriority, open, onClose }: { editing: Provider | null; nextPriority: number; open: boolean; onClose: () => void }) {
  const invalidate = useInvalidate();
  const initial = (): FormState =>
    editing
      ? { provider: editing.provider, name: editing.name, base_url: editing.base_url, model: editing.model, api_key: "", tags: editing.tags.join(", "), priority: editing.priority }
      : { provider: "openrouter", name: "OpenRouter", base_url: PROVIDERS.openrouter.base_url, model: "", api_key: "", tags: "", priority: nextPriority };
  const [form, setForm] = useState<FormState>(initial);
  const [test, setTest] = useState<TestResult | null>(null);

  const body = () => {
    const data: Record<string, unknown> = {
      provider: form.provider,
      name: form.name.trim(),
      base_url: form.base_url.trim(),
      model: form.model.trim(),
      priority: form.priority,
      tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean),
    };
    if (form.api_key.trim()) data.api_key = form.api_key.trim();
    return data;
  };

  const save = useMutation({
    mutationFn: () => (editing ? patch(`/settings/llm-providers/${editing.id}`, body()) : post("/settings/llm-providers", { ...body(), enabled: true })),
    onSuccess: () => {
      toast(editing ? "Provider updated" : "Provider added", "success");
      invalidate();
      onClose();
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  const runTest = useMutation({
    mutationFn: () =>
      editing ? post<TestResult>(`/settings/llm-providers/${editing.id}/test`, body()) : post<TestResult>("/settings/llm-providers/test", body()),
    onSuccess: setTest,
    onError: (e: Error) => setTest({ success: false, detail: e.message }),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editing ? `Edit ${editing.name}` : "Add LLM provider"}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button icon={<FlaskConical className="size-3.5" />} loading={runTest.isPending} onClick={() => runTest.mutate()} disabled={!form.base_url || !form.model}>
            Test connection
          </Button>
          <Button variant="primary" loading={save.isPending} onClick={() => save.mutate()} disabled={!form.name || !form.model}>
            {editing ? "Save changes" : "Add provider"}
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
        <Field label="Model" hint={form.provider === "openrouter" ? "e.g. anthropic/claude-sonnet-4.5, openai/gpt-4.1-mini" : undefined}>
          <input className={inputClass} value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} />
        </Field>
        <Field
          label="API key"
          hint={editing ? (editing.api_key_configured ? "A key is stored. Leave blank to keep it." : "No key stored yet.") : form.provider === "ollama" ? "Not needed for local Ollama." : undefined}
        >
          <input
            type="password"
            autoComplete="new-password"
            className={inputClass}
            placeholder={editing?.api_key_configured ? "••••••••  (unchanged)" : ""}
            value={form.api_key}
            onChange={(e) => setForm({ ...form, api_key: e.target.value })}
          />
        </Field>
        <Field label="Priority" hint="Lowest number is tried first; the rest are fail-over in order.">
          <input type="number" min={0} className={inputClass} value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} />
        </Field>
        <div className="col-span-2">
          <Field label="Agent tags (optional)" hint="Pin specific agents to this model, e.g. agent:investigation, agent:reporting. Untagged agents follow the priority order.">
            <input className={inputClass} value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
          </Field>
        </div>
        {test && (
          <div className={`col-span-2 rounded-md border p-2 text-xs ${test.success ? "border-good/40 text-good" : "border-critical/50 text-critical"}`}>
            {test.detail}
            {test.response_preview ? <div className="mt-1 font-mono text-ink-3">{test.response_preview}</div> : null}
          </div>
        )}
      </div>
    </Modal>
  );
}

/** Manage LLM providers: API keys, models and the order the agents try them in. Admin only (settings.manage). */
export default function LLMProvidersPanel({ className }: { className?: string }) {
  const invalidate = useInvalidate();
  const providers = useQuery({ queryKey: ["providers"], queryFn: () => get<Paginated<Provider> | Provider[]>("/settings/llm-providers") });
  const [modal, setModal] = useState<{ editing: Provider | null } | null>(null);
  const list = [...(Array.isArray(providers.data) ? providers.data : providers.data?.results ?? [])].sort(
    (a, b) => a.priority - b.priority || a.name.localeCompare(b.name),
  );
  const firstEnabled = list.find((p) => p.enabled)?.id;

  const toggle = useMutation({
    mutationFn: (p: Provider) => patch(`/settings/llm-providers/${p.id}`, { enabled: !p.enabled }),
    onSuccess: invalidate,
    onError: (e: Error) => toast(e.message, "error"),
  });
  const remove = useMutation({
    mutationFn: (p: Provider) => del(`/settings/llm-providers/${p.id}`),
    onSuccess: invalidate,
    onError: (e: Error) => toast(e.message, "error"),
  });
  // Move one row up/down, then renumber everything 10, 20, 30... so the order is unambiguous.
  const move = useMutation({
    mutationFn: async ({ index, dir }: { index: number; dir: -1 | 1 }) => {
      const order = [...list];
      const target = index + dir;
      [order[index], order[target]] = [order[target], order[index]];
      const updates = order.map((p, i) => ({ p, priority: (i + 1) * 10 })).filter(({ p, priority }) => p.priority !== priority);
      for (const { p, priority } of updates) await patch(`/settings/llm-providers/${p.id}`, { priority });
    },
    onSuccess: invalidate,
    onError: (e: Error) => {
      toast(e.message, "error");
      invalidate();
    },
  });

  return (
    <Card
      title="LLM providers & priority"
      className={className}
      action={
        <Button size="sm" variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setModal({ editing: null })}>
          Add provider
        </Button>
      }
      bodyClassName="p-0"
    >
      {providers.isLoading ? (
        <Spinner />
      ) : list.length ? (
        <>
          <Table head={["Order", "Name", "Provider", "Model", "API key", "Tags", "Enabled", ""]}>
            {list.map((p, i) => (
              <tr key={p.id} className={p.enabled ? "" : "opacity-60"}>
                <td className="whitespace-nowrap px-3 py-2.5">
                  <div className="flex items-center gap-1">
                    <span className="w-6 tabular-nums text-ink-3">{i + 1}</span>
                    <button className="text-ink-3 hover:text-ink disabled:opacity-30" disabled={i === 0 || move.isPending} onClick={() => move.mutate({ index: i, dir: -1 })} title="Higher priority">
                      <ArrowUp className="size-4" />
                    </button>
                    <button
                      className="text-ink-3 hover:text-ink disabled:opacity-30"
                      disabled={i === list.length - 1 || move.isPending}
                      onClick={() => move.mutate({ index: i, dir: 1 })}
                      title="Lower priority"
                    >
                      <ArrowDown className="size-4" />
                    </button>
                  </div>
                </td>
                <td className="px-3 py-2.5 font-medium">
                  {p.name}
                  {p.id === firstEnabled && <Badge tone="good" className="ml-2">primary</Badge>}
                </td>
                <td className="px-3 py-2.5 text-xs text-ink-2">{PROVIDERS[p.provider]?.label ?? p.provider}</td>
                <td className="px-3 py-2.5 font-mono text-xs">{p.model}</td>
                <td className="px-3 py-2.5">
                  {p.api_key_configured ? <Badge tone="good">set</Badge> : p.provider === "ollama" ? <Badge>not needed</Badge> : <Badge tone="warning">missing</Badge>}
                </td>
                <td className="px-3 py-2.5 text-xs text-ink-3">{p.tags.join(", ") || "-"}</td>
                <td className="px-3 py-2.5">
                  <button onClick={() => toggle.mutate(p)} title="Toggle">
                    <Badge tone={p.enabled ? "good" : "neutral"}>{p.enabled ? "On" : "Off"}</Badge>
                  </button>
                </td>
                <td className="whitespace-nowrap px-3 py-2.5 text-right">
                  <button onClick={() => setModal({ editing: p })} className="mr-3 text-ink-3 hover:text-ink" title="Edit / set API key">
                    <Pencil className="size-4" />
                  </button>
                  <button onClick={() => confirm(`Remove ${p.name}?`) && remove.mutate(p)} className="text-ink-3 hover:text-critical" title="Remove">
                    <Trash2 className="size-4" />
                  </button>
                </td>
              </tr>
            ))}
          </Table>
          <div className="border-t border-line px-3 py-2 text-xs text-ink-3">
            Agents call the top enabled provider first. If it fails, is unreachable, runs out of credits or rejects the key, the next one is tried, and finally the
            offline engine (in Auto mode). Agent tags override the order for that agent.
          </div>
        </>
      ) : (
        <div className="p-4 text-sm text-ink-3">
          No provider configured, so the agents use any <code>*_API_KEY</code> set in the backend <code>.env</code>, otherwise the offline engine. Add a provider
          here to control keys and order from the UI.
        </div>
      )}
      {modal && (
        <ProviderModal
          key={modal.editing?.id ?? "new"}
          open
          editing={modal.editing}
          nextPriority={(list.length + 1) * 10}
          onClose={() => setModal(null)}
        />
      )}
    </Card>
  );
}
