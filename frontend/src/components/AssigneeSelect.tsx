"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { cx, inputClass } from "@/components/ui";
import { get, patch } from "@/lib/api";
import { toast } from "@/lib/toast";
import type { Case, User } from "@/lib/types";

export interface UserOption {
  id: number;
  label: string;
  username: string;
  role: string;
}

/** Roles that can work a case (auditors are read-only). */
const ASSIGNABLE_ROLES = "tier1_analyst,tier2_responder,soc_manager,admin";

export function useAssignableUsers(enabled = true) {
  return useQuery({
    queryKey: ["user-options", "assignable"],
    queryFn: () => get<UserOption[]>("/auth/user-options", { role: ASSIGNABLE_ROLES }),
    enabled,
    staleTime: 60_000,
  });
}

/** SOC admins and managers hand out work; everyone else can only pick cases up for themselves. */
export function canAssignOthers(user: User | null | undefined) {
  return !!user && (user.role === "admin" || user.role === "soc_manager");
}

/** Inline dropdown that (re)assigns a case. The assignee gets an inbox message and an email. */
export default function AssigneeSelect({ c, className }: { c: Pick<Case, "id" | "assignee" | "assignee_name" | "status">; className?: string }) {
  const qc = useQueryClient();
  const users = useAssignableUsers();
  const assign = useMutation({
    mutationFn: (assignee: number | null) =>
      patch(`/cases/${c.id}`, { assignee, ...(assignee && c.status === "New" ? { status: "In Progress" } : {}) }),
    onSuccess: (_, assignee) => {
      const who = users.data?.find((u) => u.id === assignee)?.label;
      toast(who ? `Assigned to ${who}. They will get an email.` : "Case unassigned", "success");
      qc.invalidateQueries({ queryKey: ["cases"] });
      qc.invalidateQueries({ queryKey: ["case", c.id] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  const options = users.data ?? [];
  const missingCurrent = c.assignee != null && !options.some((u) => u.id === c.assignee);

  return (
    <select
      className={cx(inputClass, "h-8 w-44 py-1 text-xs", !c.assignee && "text-ink-3", className)}
      value={c.assignee ?? ""}
      disabled={assign.isPending || users.isLoading}
      onClick={(e) => e.stopPropagation()}
      onChange={(e) => assign.mutate(e.target.value ? Number(e.target.value) : null)}
      title="Assign this case"
    >
      <option value="">Unassigned</option>
      {missingCurrent && <option value={c.assignee!}>{c.assignee_name}</option>}
      {options.map((u) => (
        <option key={u.id} value={u.id}>
          {u.label}
        </option>
      ))}
    </select>
  );
}
