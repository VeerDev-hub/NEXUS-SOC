"use client";

import Link from "next/link";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Bot, Check, Lock, PlugZap, X } from "lucide-react";
import { ROLE_REQUIREMENT_LABEL } from "@/lib/agents";
import { post } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime, timeAgo } from "@/lib/format";
import { toast } from "@/lib/toast";
import type { ActionProposal, Role } from "@/lib/types";
import { Badge, Button, cx, inputClass } from "../ui";

const RISK_TONE = { Low: "good", Medium: "warning", High: "serious", Critical: "critical" } as const;

/** Mirrors the backend policy (apps/agentic/multiagent/actions.py::can_approve). */
export function canApprove(role: Role | undefined, p: ActionProposal) {
  if (!role) return false;
  if (role === "admin") return true;
  if (p.required_role === "soc_manager") return role === "soc_manager";
  return role === "tier2_responder" || role === "soc_manager";
}

export default function ProposalCard({ proposal, showCase = false }: { proposal: ActionProposal; showCase?: boolean }) {
  const qc = useQueryClient();
  const user = useAuth((s) => s.user);
  const [note, setNote] = useState("");
  const allowed = canApprove(user?.role, proposal) && user?.permissions.includes("actions.approve");

  const decide = useMutation({
    mutationFn: (approve: boolean) => post<ActionProposal>(`/action-proposals/${proposal.id}/decide`, { approve, note }),
    onSuccess: (p) => {
      toast(p.status === "Executed" ? `${p.action_label} executed on ${p.target}` : `${p.action_label} rejected`, p.status === "Executed" ? "success" : "info");
      qc.invalidateQueries({ queryKey: ["proposals"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
    onError: (e: Error) => toast(e.message, "error"),
  });

  const pending = proposal.status === "Pending";
  return (
    <div className={cx("rounded-lg border bg-panel-2 p-3", pending ? "border-line-strong" : "border-line opacity-90")}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={RISK_TONE[proposal.risk_level]}>{proposal.risk_level} risk</Badge>
        <span className="text-sm font-semibold">{proposal.action_label}</span>
        <code className="rounded bg-bg px-1.5 py-0.5 text-xs text-ink-2">{proposal.target}</code>
        <span className="ml-auto text-[11px] text-ink-3">{timeAgo(proposal.created_at)}</span>
      </div>
      {showCase && (
        <Link href={`/cases/${proposal.case_pk}`} className="mt-1 block truncate text-xs text-[#8fbcf3] hover:underline">
          {proposal.case_id.toUpperCase()} · {proposal.case_title}
        </Link>
      )}
      <p className="mt-2 flex gap-1.5 text-xs text-ink-2">
        <Bot className="mt-0.5 size-3.5 shrink-0 text-ink-3" />
        {proposal.rationale}
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] text-ink-3">
        <span className="flex items-center gap-1">
          <PlugZap className="size-3" /> {proposal.connector}
        </span>
        <span className="flex items-center gap-1">
          <Lock className="size-3" /> Approver: {ROLE_REQUIREMENT_LABEL[proposal.required_role]}
        </span>
      </div>

      {pending ? (
        allowed ? (
          <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-3">
            <input className={cx(inputClass, "h-8 flex-1 py-1 text-xs")} placeholder="Decision note (optional)" value={note} onChange={(e) => setNote(e.target.value)} />
            <Button size="sm" variant="success" icon={<Check className="size-3.5" />} loading={decide.isPending && decide.variables} onClick={() => decide.mutate(true)}>
              Approve & execute
            </Button>
            <Button size="sm" variant="ghost" icon={<X className="size-3.5" />} loading={decide.isPending && !decide.variables} onClick={() => decide.mutate(false)}>
              Reject
            </Button>
          </div>
        ) : (
          <div className="mt-3 border-t border-line pt-2 text-xs text-ink-3">
            Waiting for a {ROLE_REQUIREMENT_LABEL[proposal.required_role]} to approve.
          </div>
        )
      ) : (
        <div className="mt-3 border-t border-line pt-2 text-xs">
          <span className={cx("font-medium", proposal.status === "Executed" ? "text-[#6fd36f]" : proposal.status === "Rejected" ? "text-ink-3" : "text-critical")}>
            {proposal.status}
          </span>
          <span className="text-ink-3">
            {" "}
            {proposal.auto_approved ? "automatically by policy" : proposal.decided_by ? `by ${proposal.decided_by.name}` : ""} · {formatDateTime(proposal.decided_at)}
          </span>
          {proposal.execution_result?.message && <div className="mt-1 font-mono text-[11px] text-ink-3">{proposal.execution_result.message} [{proposal.execution_result.reference}]</div>}
          {proposal.decision_note && !proposal.auto_approved && <div className="mt-1 text-ink-3">Note: {proposal.decision_note}</div>}
        </div>
      )}
    </div>
  );
}
