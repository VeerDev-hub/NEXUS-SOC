"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { ArrowLeft, ArrowUpRight, Bot, CheckCircle2, Hand, Play, Printer, ShieldCheck, UserPlus } from "lucide-react";
import AgentGraph from "@/components/agents/AgentGraph";
import AgentTimeline from "@/components/agents/AgentTimeline";
import ProposalCard from "@/components/agents/ProposalCard";
import ReportView from "@/components/agents/ReportView";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorBox,
  Field,
  inputClass,
  ModeBadge,
  Modal,
  SeverityBadge,
  Spinner,
  StatusBadge,
  Table,
  Tabs,
  VerdictBadge,
} from "@/components/ui";
import { get, patch, post } from "@/lib/api";
import { can, useAuth } from "@/lib/auth";
import { formatDateTime, formatDuration, timeAgo } from "@/lib/format";
import { useCase, useCaseAlerts, useCaseArtifacts, useCaseEnrichments, useCaseRuns, useProposals, useRun } from "@/lib/queries";
import { toast } from "@/lib/toast";
import type { Case } from "@/lib/types";

type Tab = "agents" | "report" | "evidence";
const VERDICTS = ["True Positive", "False Positive", "Benign", "Suspicious", "Insufficient Data"];

interface UserOption {
  id: number;
  label: string;
  username: string;
  role: string;
}

/** Hand the case to a teammate; they get an inbox message and an email with the case details. */
function AssignModal({ caseId, current, status, open, onClose }: { caseId: string; current: number | null; status: string; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const options = useQuery({
    queryKey: ["user-options", "assignable"],
    queryFn: () => get<UserOption[]>("/auth/user-options", { role: "tier1_analyst,tier2_responder,soc_manager,admin" }),
    enabled: open,
  });
  const [assignee, setAssignee] = useState<string>("");
  const selected = assignee || (current ? String(current) : "");
  const save = useMutation({
    mutationFn: () => patch(`/cases/${caseId}`, { assignee: Number(selected), status: status === "New" ? "In Progress" : status }),
    onSuccess: () => {
      const who = options.data?.find((o) => String(o.id) === selected)?.label ?? "teammate";
      toast(`Case assigned to ${who}. They will get an email.`, "success");
      qc.invalidateQueries({ queryKey: ["case", caseId] });
      qc.invalidateQueries({ queryKey: ["cases"] });
      onClose();
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Assign case"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} disabled={!selected || Number(selected) === current} onClick={() => save.mutate()}>
            Assign
          </Button>
        </>
      }
    >
      <Field label="Teammate" hint="They receive an inbox message and an email with the case summary and a link.">
        {options.isLoading ? (
          <Spinner />
        ) : (
          <select className={inputClass} value={selected} onChange={(e) => setAssignee(e.target.value)}>
            <option value="">Select a teammate...</option>
            {(options.data ?? []).map((o) => (
              <option key={o.id} value={o.id}>
                {o.label} ({o.username})
              </option>
            ))}
          </select>
        )}
      </Field>
    </Modal>
  );
}

function RunAgentsModal({ caseId, open, onClose }: { caseId: string; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [input, setInput] = useState("");
  const run = useMutation({
    mutationFn: () => post(`/cases/${caseId}/agent-runs`, { user_input: input }),
    onSuccess: () => {
      toast("Agent team dispatched. Steps will stream in live.", "info");
      qc.invalidateQueries({ queryKey: ["runs", "case", caseId] });
      onClose();
      setInput("");
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Dispatch the AI agent team"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" icon={<Play className="size-4" />} loading={run.isPending} onClick={() => run.mutate()}>
            Run agents
          </Button>
        </>
      }
    >
      <p className="mb-3 text-sm text-ink-2">
        The Supervisor will route this case through the specialist agents. Add a hint if you want them to focus on something.
      </p>
      <Field label="Analyst guidance (optional)">
        <textarea className={inputClass} rows={3} value={input} onChange={(e) => setInput(e.target.value)} placeholder="e.g. Check whether 45.77.10.99 appears in other cases" />
      </Field>
    </Modal>
  );
}

function ResolveModal({ c, open, onClose }: { c: Case; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [verdict, setVerdict] = useState(c.verdict_ai || "True Positive");
  const [summary, setSummary] = useState("");
  const resolve = useMutation({
    mutationFn: () => patch(`/cases/${c.id}`, { status: "Resolved", verdict, summary }),
    onSuccess: () => {
      toast(`${c.case_id.toUpperCase()} resolved`, "success");
      qc.invalidateQueries({ queryKey: ["case", c.id] });
      qc.invalidateQueries({ queryKey: ["cases"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
      onClose();
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`Resolve ${c.case_id.toUpperCase()}`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="success" loading={resolve.isPending} onClick={() => resolve.mutate()} disabled={!summary.trim()}>
            Resolve case
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Analyst verdict" hint={c.verdict_ai ? `AI verdict: ${c.verdict_ai}` : undefined}>
          <select className={inputClass} value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            {VERDICTS.map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </Field>
        <Field label="Closure summary">
          <textarea className={inputClass} rows={4} value={summary} onChange={(e) => setSummary(e.target.value)} placeholder="What was done and why it is safe to close" />
        </Field>
      </div>
    </Modal>
  );
}

function EscalateModal({ c, open, onClose }: { c: Case; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const escalate = useMutation({
    mutationFn: () => post<Case>(`/cases/${c.id}/escalate`, { reason }),
    onSuccess: () => {
      toast(`${c.case_id.toUpperCase()} escalated to Tier-2`, "success");
      qc.invalidateQueries({ queryKey: ["case", c.id] });
      qc.invalidateQueries({ queryKey: ["cases"] });
      onClose();
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Escalate to Tier-2"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={escalate.isPending} disabled={!reason.trim()} onClick={() => escalate.mutate()}>
            Escalate
          </Button>
        </>
      }
    >
      <Field label="Why does this need a responder?">
        <textarea className={inputClass} rows={3} value={reason} onChange={(e) => setReason(e.target.value)} />
      </Field>
    </Modal>
  );
}

export default function CaseWarRoom() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const user = useAuth((s) => s.user);
  const caseQ = useCase(id);
  const runsQ = useCaseRuns(id);
  const proposalsQ = useProposals({ case: id });
  const alertsQ = useCaseAlerts(id);
  const artifactsQ = useCaseArtifacts(id);
  const enrichQ = useCaseEnrichments(id);

  const [tab, setTab] = useState<Tab>("agents");
  // A manual run selection only sticks until a newer run starts; then we follow the live one.
  const [selection, setSelection] = useState<{ id: string; latest?: string } | null>(null);
  const [highlight, setHighlight] = useState<string | undefined>();
  const [modal, setModal] = useState<"run" | "resolve" | "escalate" | "assign" | null>(null);

  const latestRunId = runsQ.data?.[0]?.id;
  const runId = selection && selection.latest === latestRunId ? selection.id : latestRunId;
  const runQ = useRun(runId);
  const run = runQ.data;

  const assign = useMutation({
    mutationFn: () => patch(`/cases/${id}`, { assignee: user?.id, status: caseQ.data?.status === "New" ? "In Progress" : caseQ.data?.status }),
    onSuccess: () => {
      toast("Case assigned to you", "success");
      qc.invalidateQueries({ queryKey: ["case", id] });
      qc.invalidateQueries({ queryKey: ["cases"] });
    },
    onError: (e: Error) => toast(e.message, "error"),
  });

  const pending = useMemo(() => (proposalsQ.data?.results ?? []).filter((p) => p.status === "Pending"), [proposalsQ.data]);
  const decided = useMemo(() => (proposalsQ.data?.results ?? []).filter((p) => p.status !== "Pending"), [proposalsQ.data]);

  if (caseQ.isLoading) return <Spinner />;
  if (caseQ.error) return <ErrorBox error={caseQ.error} />;
  const c = caseQ.data!;
  const closed = c.status === "Resolved" || c.status === "Closed";

  return (
    <div className="mx-auto max-w-[1400px]">
      <Link href="/cases" className="mb-3 inline-flex items-center gap-1 text-xs text-ink-3 hover:text-ink no-print">
        <ArrowLeft className="size-3.5" /> Cases
      </Link>

      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-xs text-ink-3">
            <span className="font-mono">{c.case_id.toUpperCase()}</span>
            <span>·</span>
            <span>{c.category || "Uncategorised"}</span>
            <span>·</span>
            <span>opened {timeAgo(c.created_at)}</span>
          </div>
          <h1 className="mt-1 text-xl font-semibold tracking-tight">{c.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <SeverityBadge value={c.severity} />
            <StatusBadge value={c.status} />
            <Badge tone={c.tier === "L2" ? "serious" : "neutral"}>{c.tier === "L2" ? "Tier-2 queue" : "Tier-1 queue"}</Badge>
            {c.verdict_ai && (
              <span className="flex items-center gap-1 text-xs text-ink-3">
                <Bot className="size-3.5" /> AI: <VerdictBadge value={c.verdict_ai} />
              </span>
            )}
            {c.verdict && (
              <span className="flex items-center gap-1 text-xs text-ink-3">
                Analyst: <VerdictBadge value={c.verdict} />
              </span>
            )}
            <span className="text-xs text-ink-3">Assignee: {c.assignee_name || "unassigned"}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2 no-print">
          {can(user, "agents.run") && !closed && (
            <Button variant="primary" icon={<Play className="size-4" />} onClick={() => setModal("run")} disabled={run?.status === "Running"}>
              {run?.status === "Running" ? "Agents running..." : "Run AI agents"}
            </Button>
          )}
          {can(user, "records.write") && !closed && c.assignee !== user?.id && (
            <Button icon={<Hand className="size-4" />} loading={assign.isPending} onClick={() => assign.mutate()}>
              Assign to me
            </Button>
          )}
          {can(user, "records.write") && !closed && (
            <Button icon={<UserPlus className="size-4" />} onClick={() => setModal("assign")}>
              {c.assignee ? "Reassign" : "Assign"}
            </Button>
          )}
          {can(user, "cases.escalate") && c.tier === "L1" && !closed && (
            <Button icon={<ArrowUpRight className="size-4" />} onClick={() => setModal("escalate")}>
              Escalate
            </Button>
          )}
          {can(user, "cases.close") && !closed && (
            <Button variant="success" icon={<CheckCircle2 className="size-4" />} onClick={() => setModal("resolve")}>
              Resolve
            </Button>
          )}
          <Button variant="ghost" icon={<Printer className="size-4" />} onClick={() => window.print()}>
            Export
          </Button>
        </div>
      </div>

      {c.escalated_at && (
        <div className="mb-4 rounded-lg border border-serious/40 bg-serious/10 px-4 py-2.5 text-sm">
          <span className="font-medium text-serious">Escalated {timeAgo(c.escalated_at)}</span>
          <span className="text-ink-3"> by {c.escalated_by_name}. </span>
          <span className="text-ink-2">{c.escalation_reason}</span>
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="min-w-0 space-y-4">
          <Tabs<Tab>
            value={tab}
            onChange={setTab}
            tabs={[
              { key: "agents", label: "Agent activity" },
              { key: "report", label: "Incident report" },
              { key: "evidence", label: `Evidence (${alertsQ.data?.count ?? 0} alerts)` },
            ]}
          />

          {tab === "agents" && (
            <>
              {!runsQ.data?.length ? (
                <Card>
                  <Empty title="No agent run yet" icon={<Bot className="size-8" />}>
                    Runs start automatically when an alert arrives, or click <b>Run AI agents</b>.
                  </Empty>
                </Card>
              ) : (
                <>
                  <Card
                    title={
                      <span className="flex items-center gap-2">
                        Agent routing
                        {run?.status === "Running" && <Badge tone="accent">live</Badge>}
                        {run && run.status !== "Running" && <ModeBadge mode={run.llm_mode} />}
                      </span>
                    }
                    action={
                      runsQ.data.length > 1 && (
                        <select className="rounded border border-line-strong bg-bg px-2 py-1 text-xs" value={runId} onChange={(e) => setSelection({ id: e.target.value, latest: latestRunId })}>
                          {runsQ.data.map((r, i) => (
                            <option key={r.id} value={r.id}>
                              Run {runsQ.data.length - i} · {formatDateTime(r.started_at)} · {r.status}
                            </option>
                          ))}
                        </select>
                      )
                    }
                  >
                    <AgentGraph
                      run={run}
                      onSelect={(s) => {
                        setHighlight(s.id);
                        document.getElementById(`step-${s.id}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
                      }}
                    />
                    {run && (
                      <div className="mt-2 flex flex-wrap justify-center gap-x-6 gap-y-1 text-xs text-ink-3">
                        <span>Trigger: {run.trigger}{run.triggered_by ? ` by ${run.triggered_by.name}` : ""}</span>
                        <span>Duration: {run.status === "Running" ? "running" : formatDuration(run.duration_ms)}</span>
                        <span>Tokens: {run.total_tokens}</span>
                        {run.final_verdict && (
                          <span className="flex items-center gap-1">
                            Outcome: <VerdictBadge value={run.final_verdict} />
                          </span>
                        )}
                      </div>
                    )}
                  </Card>
                  {runQ.isLoading ? <Spinner /> : <AgentTimeline steps={run?.steps ?? []} highlightId={highlight} />}
                  {run?.user_input && <p className="text-xs text-ink-3">Analyst guidance: &ldquo;{run.user_input}&rdquo;</p>}
                </>
              )}
            </>
          )}

          {tab === "report" && <ReportView report={run?.report} title={c.title} meta={run ? `Generated by the agent team · ${formatDateTime(run.completed_at)}` : undefined} />}

          {tab === "evidence" && (
            <div className="space-y-4">
              <Card title="Alerts" bodyClassName="p-0">
                <Table head={["Alert", "Rule", "Severity", "ATT&CK", "First seen"]}>
                  {(alertsQ.data?.results ?? []).map((a) => (
                    <tr key={a.id}>
                      <td className="px-3 py-2">
                        <div className="font-medium">{a.title}</div>
                        <div className="text-xs text-ink-3">{a.desc}</div>
                      </td>
                      <td className="px-3 py-2 text-xs text-ink-3">{a.rule_name}</td>
                      <td className="px-3 py-2">
                        <SeverityBadge value={a.severity} />
                      </td>
                      <td className="px-3 py-2 text-xs">{a.technique || "-"}</td>
                      <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-3">{formatDateTime(a.first_seen_time)}</td>
                    </tr>
                  ))}
                </Table>
              </Card>
              <div className="grid gap-4 lg:grid-cols-2">
                <Card title="Artifacts" bodyClassName="p-0">
                  <Table head={["Type", "Value", "Role"]}>
                    {(artifactsQ.data?.results ?? []).map((a) => (
                      <tr key={a.id}>
                        <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-3">{a.type}</td>
                        <td className="max-w-[260px] truncate px-3 py-2 font-mono text-xs" title={a.value}>
                          {a.value}
                        </td>
                        <td className="px-3 py-2 text-xs text-ink-3">{a.role}</td>
                      </tr>
                    ))}
                  </Table>
                </Card>
                <Card title="Enrichments (written by agents)">
                  <ul className="space-y-2">
                    {(enrichQ.data?.results ?? []).map((e) => (
                      <li key={e.id} className="text-sm">
                        <div className="flex items-center gap-2">
                          <Badge>{e.type}</Badge>
                          <code className="text-xs">{e.value}</code>
                        </div>
                        <div className="mt-0.5 text-xs text-ink-3">{e.desc}</div>
                      </li>
                    ))}
                    {!enrichQ.data?.results.length && <li className="text-sm text-ink-3">None yet.</li>}
                  </ul>
                </Card>
              </div>
            </div>
          )}
        </div>

        <aside className="space-y-4">
          <Card
            title={
              <span className="flex items-center gap-2">
                <ShieldCheck className="size-4 text-ink-3" /> Response actions
                {pending.length > 0 && <Badge tone="warning">{pending.length} awaiting approval</Badge>}
              </span>
            }
          >
            <div className="space-y-3">
              {pending.map((p) => (
                <ProposalCard key={p.id} proposal={p} />
              ))}
              {decided.map((p) => (
                <ProposalCard key={p.id} proposal={p} />
              ))}
              {!proposalsQ.data?.results.length && <p className="text-sm text-ink-3">The Response Agent has not proposed any actions.</p>}
            </div>
          </Card>

          <Card title="AI assessment vs analyst">
            <div className="space-y-2 text-sm">
              {[
                ["Verdict", c.verdict_ai, c.verdict],
                ["Severity", c.severity_ai, c.severity],
                ["Impact", c.impact_ai, c.impact],
                ["Priority", c.priority_ai, c.priority],
                ["Confidence", c.confidence_ai, c.confidence],
              ].map(([k, ai, human]) => (
                <div key={k} className="grid grid-cols-[90px_1fr_1fr] gap-2">
                  <span className="text-xs text-ink-3">{k}</span>
                  <span className="text-xs">{ai || "-"}</span>
                  <span className="text-xs text-ink-2">{human || "-"}</span>
                </div>
              ))}
              <div className="grid grid-cols-[90px_1fr_1fr] gap-2 border-t border-line pt-2 text-[11px] text-ink-3">
                <span />
                <span>AI agents</span>
                <span>Analyst</span>
              </div>
            </div>
            {c.summary && <p className="mt-3 border-t border-line pt-3 text-xs text-ink-2">{c.summary}</p>}
          </Card>

          <Card title="Description">
            <p className="text-sm text-ink-2">{c.description || "-"}</p>
            <div className="mt-2 flex flex-wrap gap-1">
              {c.tags.map((t) => (
                <Badge key={t}>{t}</Badge>
              ))}
            </div>
          </Card>
        </aside>
      </div>

      <RunAgentsModal caseId={id} open={modal === "run"} onClose={() => setModal(null)} />
      {modal === "assign" && <AssignModal caseId={id} current={c.assignee} status={c.status} open onClose={() => setModal(null)} />}
      {modal === "resolve" && <ResolveModal c={c} open onClose={() => setModal(null)} />}
      {modal === "escalate" && <EscalateModal c={c} open onClose={() => setModal(null)} />}
    </div>
  );
}
