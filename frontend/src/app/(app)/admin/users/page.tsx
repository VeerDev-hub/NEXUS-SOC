"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { KeyRound, UserPlus } from "lucide-react";
import { RequirePermission } from "@/components/AppShell";
import { Badge, Button, Card, cx, Field, inputClass, Modal, PageHeader, Spinner, Table } from "@/components/ui";
import { get, patch, post } from "@/lib/api";
import { ROLE_LABEL } from "@/lib/auth";
import { displayName, timeAgo } from "@/lib/format";
import { toast } from "@/lib/toast";
import type { Paginated, Role, User } from "@/lib/types";

interface RoleInfo {
  value: Role;
  label: string;
  description: string;
  permissions: string[];
}

interface Credentials {
  username: string;
  password?: string;
}

export default function UsersPage() {
  return (
    <RequirePermission perm="users.manage">
      <Users />
    </RequirePermission>
  );
}

function Users() {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => get<Paginated<User>>("/auth/users", { page_size: 100 }) });
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => get<RoleInfo[]>("/auth/roles") });
  const [createOpen, setCreateOpen] = useState(false);
  const [creds, setCreds] = useState<Credentials | null>(null);
  const [form, setForm] = useState({ username: "", first_name: "", last_name: "", email: "", title: "", role: "tier1_analyst" as Role });

  const refresh = () => qc.invalidateQueries({ queryKey: ["users"] });
  const create = useMutation({
    mutationFn: () => post<{ credentials: Credentials }>("/auth/users", { ...form, auth_type: "local" }),
    onSuccess: (data) => {
      refresh();
      setCreateOpen(false);
      setCreds(data.credentials);
      setForm({ username: "", first_name: "", last_name: "", email: "", title: "", role: "tier1_analyst" });
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Partial<User> }) => patch(`/auth/users/${id}`, body),
    onSuccess: () => {
      refresh();
      toast("User updated", "success");
    },
    onError: (e: Error) => toast(e.message, "error"),
  });
  const reset = useMutation({
    mutationFn: (id: number) => post<{ credentials: Credentials }>(`/auth/users/${id}/reset_password`),
    onSuccess: (d) => setCreds(d.credentials),
    onError: (e: Error) => toast(e.message, "error"),
  });

  return (
    <div className="mx-auto max-w-[1300px]">
      <PageHeader
        title="Users & roles"
        subtitle="Every permission in the platform comes from the role assigned here."
        actions={
          <Button variant="primary" icon={<UserPlus className="size-4" />} onClick={() => setCreateOpen(true)}>
            New user
          </Button>
        }
      />
      <Card bodyClassName="p-0" className="mb-5">
        {users.isLoading ? (
          <Spinner />
        ) : (
          <Table head={["User", "Title", "Role", "Status", "Last login", ""]}>
            {(users.data?.results ?? []).map((u) => (
              <tr key={u.id}>
                <td className="px-3 py-2.5">
                  <div className="font-medium">{displayName(u)}</div>
                  <div className="text-xs text-ink-3">
                    {u.username} · {u.email || "no email"}
                  </div>
                </td>
                <td className="px-3 py-2.5 text-xs text-ink-2">{u.title || "-"}</td>
                <td className="px-3 py-2.5">
                  <select
                    className={cx(inputClass, "h-8 w-48 py-1 text-xs")}
                    value={u.role}
                    onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value as Role } })}
                  >
                    {(Object.keys(ROLE_LABEL) as Role[]).map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABEL[r]}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-2.5">
                  <button onClick={() => update.mutate({ id: u.id, body: { is_active: !u.is_active } })}>
                    <Badge tone={u.is_active ? "good" : "neutral"}>{u.is_active ? "Active" : "Disabled"}</Badge>
                  </button>
                </td>
                <td className="px-3 py-2.5 text-xs text-ink-3">{u.last_login ? timeAgo(u.last_login) : "never"}</td>
                <td className="px-3 py-2.5 text-right">
                  <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" />} onClick={() => reset.mutate(u.id)}>
                    Reset password
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <h2 className="mb-3 text-sm font-semibold">Role definitions</h2>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(roles.data ?? []).map((r) => (
          <Card key={r.value}>
            <div className="font-medium">{r.label}</div>
            <p className="mt-1 text-xs text-ink-3">{r.description}</p>
            <div className="mt-2 flex flex-wrap gap-1">
              {r.permissions.map((p) => (
                <Badge key={p}>{p}</Badge>
              ))}
            </div>
          </Card>
        ))}
      </div>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="New user"
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" loading={create.isPending} disabled={!form.username.trim()} onClick={() => create.mutate()}>
              Create
            </Button>
          </>
        }
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Username">
            <input className={inputClass} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </Field>
          <Field label="Role">
            <select className={inputClass} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {(Object.keys(ROLE_LABEL) as Role[]).map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="First name">
            <input className={inputClass} value={form.first_name} onChange={(e) => setForm({ ...form, first_name: e.target.value })} />
          </Field>
          <Field label="Last name">
            <input className={inputClass} value={form.last_name} onChange={(e) => setForm({ ...form, last_name: e.target.value })} />
          </Field>
          <Field label="Email">
            <input className={inputClass} value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          </Field>
          <Field label="Job title">
            <input className={inputClass} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
          </Field>
        </div>
      </Modal>

      <Modal open={!!creds} onClose={() => setCreds(null)} title="Credentials" footer={<Button onClick={() => setCreds(null)}>Done</Button>}>
        <p className="text-sm text-ink-2">Share these with the user. The password is shown only once.</p>
        <div className="mt-3 space-y-1 rounded-md border border-line-strong bg-bg p-3 font-mono text-sm">
          <div>username: {creds?.username}</div>
          <div>password: {creds?.password}</div>
        </div>
      </Modal>
    </div>
  );
}
