"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { BookOpen, Plus } from "lucide-react";
import { Badge, Button, Card, Empty, Field, inputClass, Modal, PageHeader, Spinner } from "@/components/ui";
import { get, post } from "@/lib/api";
import { can, useAuth } from "@/lib/auth";
import { formatDateTime } from "@/lib/format";
import { toast } from "@/lib/toast";
import type { Paginated } from "@/lib/types";

interface Knowledge {
  id: string;
  knowledge_id: string;
  title: string;
  body: string;
  tags: string[];
  source: string;
  case_readable_id: string;
  created_at: string;
}

export default function KnowledgePage() {
  const qc = useQueryClient();
  const user = useAuth((s) => s.user);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ title: "", body: "", tags: "" });
  const q = useQuery({ queryKey: ["knowledge"], queryFn: () => get<Paginated<Knowledge>>("/knowledge", { page_size: 100, ordering: "-created_at" }) });
  const create = useMutation({
    mutationFn: () => post("/knowledge", { title: form.title, body: form.body, tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean) }),
    onSuccess: () => {
      toast("Knowledge saved. Agents will use it in future triage.", "success");
      qc.invalidateQueries({ queryKey: ["knowledge"] });
      setOpen(false);
      setForm({ title: "", body: "", tags: "" });
    },
    onError: (e: Error) => toast(e.message, "error"),
  });

  return (
    <div className="mx-auto max-w-[1100px]">
      <PageHeader
        title="Knowledge base"
        subtitle="Whitelists, known-benign activity and SOPs. The Triage Agent searches this before every verdict."
        actions={
          can(user, "knowledge.write") && (
            <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setOpen(true)}>
              Add knowledge
            </Button>
          )
        }
      />
      {q.isLoading ? (
        <Spinner />
      ) : q.data?.results.length ? (
        <div className="grid gap-3 md:grid-cols-2">
          {q.data.results.map((k) => (
            <Card key={k.id}>
              <div className="flex items-center gap-2 text-xs text-ink-3">
                <span className="font-mono">{k.knowledge_id}</span>
                <Badge>{k.source}</Badge>
                {k.case_readable_id && <span>from {k.case_readable_id.toUpperCase()}</span>}
                <span className="ml-auto">{formatDateTime(k.created_at)}</span>
              </div>
              <div className="mt-1 font-medium">{k.title}</div>
              <p className="mt-1 line-clamp-4 whitespace-pre-line text-sm text-ink-2">{k.body}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {k.tags.map((t) => (
                  <Badge key={t} tone="accent">
                    {t}
                  </Badge>
                ))}
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <Card>
          <Empty title="No knowledge yet" icon={<BookOpen className="size-8" />}>
            Add a whitelist entry (for example an authorised scanner) and watch the Triage Agent mark matching alerts as false positives.
          </Empty>
        </Card>
      )}
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Add knowledge"
        wide
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" loading={create.isPending} disabled={!form.title.trim() || !form.body.trim()} onClick={() => create.mutate()}>
              Save
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Field label="Title">
            <input className={inputClass} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="Authorised vulnerability scanner" />
          </Field>
          <Field label="Body">
            <textarea className={inputClass} rows={5} value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} placeholder="Host 10.0.5.20 runs the weekly authorized Nessus scan every Sunday..." />
          </Field>
          <Field label="Tags" hint="Comma separated. Agents match on title, body and tags.">
            <input className={inputClass} value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="whitelist, scanner" />
          </Field>
        </div>
      </Modal>
    </div>
  );
}
