"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, type ReactNode } from "react";
import {
  BookOpen,
  Bot,
  BriefcaseBusiness,
  ClipboardCheck,
  FileText,
  Gauge,
  History,
  LogOut,
  Settings,
  ShieldCheck,
  Siren,
  Users,
} from "lucide-react";
import Logo from "./brand/Logo";
import { Badge, cx, Spinner } from "./ui";
import { can, ROLE_HOME, useAuth } from "@/lib/auth";
import { get } from "@/lib/api";
import { useRealtime, useRealtimeStatus } from "@/lib/realtime";
import { initials, displayName } from "@/lib/format";
import type { LLMStatus, Permission, User } from "@/lib/types";

interface NavItem {
  href: string;
  label: string;
  icon: typeof Gauge;
  perm: Permission;
  badge?: "approvals";
}

const HOME_LABEL: Record<string, string> = {
  admin: "Admin Console",
  soc_manager: "SOC Overview",
  tier1_analyst: "My Queue",
  tier2_responder: "Responder Desk",
  auditor: "Audit Overview",
};

function navFor(user: User): { section: string; items: NavItem[] }[] {
  const home: NavItem = { href: ROLE_HOME[user.role], label: HOME_LABEL[user.role], icon: Gauge, perm: "dashboard.view" };
  const sections = [
    {
      section: "Operations",
      items: [
        home,
        { href: "/cases", label: "Cases", icon: BriefcaseBusiness, perm: "records.view" },
        { href: "/alerts", label: "Alerts", icon: Siren, perm: "records.view" },
        { href: "/approvals", label: "Approvals", icon: ShieldCheck, perm: "actions.view", badge: "approvals" },
      ] as NavItem[],
    },
    {
      section: "AI Agents",
      items: [
        { href: "/agents", label: "Agent Monitor", icon: Bot, perm: "agents.view" },
        { href: "/runs", label: "Decision Trail", icon: History, perm: "agents.view" },
        { href: "/reports", label: "Reports", icon: FileText, perm: "reports.view" },
        { href: "/knowledge", label: "Knowledge Base", icon: BookOpen, perm: "records.view" },
      ] as NavItem[],
    },
    {
      section: "Governance",
      items: [
        { href: "/audit", label: "Audit Log", icon: ClipboardCheck, perm: "audit.view" },
        { href: "/admin/users", label: "Users & Roles", icon: Users, perm: "users.manage" },
        { href: "/admin/settings", label: "Platform Settings", icon: Settings, perm: "settings.manage" },
      ] as NavItem[],
    },
  ];
  return sections
    .map((s) => ({ ...s, items: s.items.filter((i) => can(user, i.perm) && !(i.href === "/audit" && i.href === home.href)) }))
    .filter((s) => s.items.length);
}

function LlmPill() {
  const { data } = useQuery({ queryKey: ["llm-status"], queryFn: () => get<LLMStatus>("/agents/llm-status"), refetchInterval: 60_000 });
  if (!data) return null;
  const online = data.effective_mode === "online";
  const provider = data.providers[0];
  return (
    <div title={data.detail} className="flex items-center gap-2 rounded-full border border-line-strong bg-panel-2 px-3 py-1 text-xs">
      <span className={cx("size-2 rounded-full", online ? "bg-good" : "bg-warning")} />
      <span className="text-ink-2">{online ? `${provider?.provider_label ?? "LLM"} · ${provider?.model}` : "Offline engine"}</span>
    </div>
  );
}

function LiveDot() {
  const connected = useRealtimeStatus((s) => s.connected);
  return (
    <div className="flex items-center gap-1.5 text-xs text-ink-3" title={connected ? "Live updates connected" : "Reconnecting to live updates"}>
      <span className={cx("size-2 rounded-full", connected ? "bg-good animate-pulse" : "bg-ink-3")} />
      {connected ? "Live" : "Offline"}
    </div>
  );
}

function PendingBadge() {
  const { data } = useQuery({
    queryKey: ["proposals", "summary"],
    queryFn: () => get<{ pending: number }>("/action-proposals/summary"),
    refetchInterval: 30_000,
  });
  if (!data?.pending) return null;
  return <span className="ml-auto rounded-full bg-warning/20 px-1.5 text-[11px] font-semibold text-warning">{data.pending}</span>;
}

export default function AppShell({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const qc = useQueryClient();
  const { user, hydrated, access, setUser, logout } = useAuth();
  useRealtime();

  useEffect(() => {
    if (hydrated && !user) router.replace("/login");
  }, [hydrated, user, router]);

  // Keep role/permissions fresh (an admin may have changed them).
  useEffect(() => {
    if (!access) return;
    get<User>("/auth/me").then(setUser).catch(() => undefined);
  }, [access, setUser]);

  if (!hydrated || !user) return <Spinner />;

  const nav = navFor(user);
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-panel md:flex no-print">
        <Link href={ROLE_HOME[user.role]} className="flex items-center gap-2.5 px-4 py-4">
          <Logo />
          <div>
            <div className="text-sm font-semibold leading-tight">NEXUS-SOC</div>
            <div className="text-[11px] text-ink-3">Multi-agent operations</div>
          </div>
        </Link>
        <nav className="flex-1 space-y-5 overflow-y-auto px-2 py-2">
          {nav.map((section) => (
            <div key={section.section}>
              <div className="px-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-ink-3">{section.section}</div>
              {section.items.map((item) => {
                const active = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href + "/"));
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cx(
                      "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors",
                      active ? "bg-accent/12 text-ink" : "text-ink-2 hover:bg-panel-2 hover:text-ink",
                    )}
                  >
                    <item.icon className={cx("size-4", active ? "text-accent" : "text-ink-3")} />
                    {item.label}
                    {item.badge === "approvals" && <PendingBadge />}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="border-t border-line p-3">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-full bg-accent/20 text-xs font-semibold text-[#8fbcf3]">
              {initials(displayName(user))}
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium">{displayName(user)}</div>
              <div className="truncate text-[11px] text-ink-3">{user.role_label}</div>
            </div>
            <button
              onClick={() => {
                logout();
                qc.clear();
                router.replace("/login");
              }}
              className="rounded p-1.5 text-ink-3 hover:bg-panel-2 hover:text-ink"
              title="Sign out"
            >
              <LogOut className="size-4" />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-12 items-center justify-between gap-4 border-b border-line bg-bg/90 px-6 backdrop-blur no-print">
          <div className="flex items-center gap-3">
            <Badge tone="accent">{user.role_label}</Badge>
            {user.title && user.title !== user.role_label && <span className="hidden text-xs text-ink-3 sm:inline">{user.title}</span>}
          </div>
          <div className="flex items-center gap-4">
            <LlmPill />
            <LiveDot />
          </div>
        </header>
        <main className="flex-1 px-6 py-6">{children}</main>
      </div>
    </div>
  );
}

export function RequirePermission({ perm, children }: { perm: Permission; children: ReactNode }) {
  const user = useAuth((s) => s.user);
  if (!can(user, perm)) {
    return (
      <div className="mx-auto mt-16 max-w-md rounded-lg border border-line bg-panel p-6 text-center">
        <div className="text-sm font-medium">Not available for your role</div>
        <p className="mt-1 text-xs text-ink-3">
          {user?.role_label} accounts do not have the <code>{perm}</code> permission.
        </p>
      </div>
    );
  }
  return <>{children}</>;
}
