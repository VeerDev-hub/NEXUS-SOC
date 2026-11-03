"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Bot, ClipboardCheck, Crosshair, KeyRound, ShieldCheck, UserCog, Users } from "lucide-react";
import Logo from "@/components/brand/Logo";
import { Button, ErrorBox, Field, inputClass, cx } from "@/components/ui";
import { ROLE_HOME, useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import type { User } from "@/lib/types";

const DEMO_PASSWORD = "SocDemo@2026";

const DEMO = [
  { username: "analyst", name: "Rohan Verma", role: "Tier-1 Analyst", icon: Crosshair, blurb: "Alert queue and AI triage review" },
  { username: "responder", name: "Ananya Iyer", role: "Tier-2 Responder", icon: ShieldCheck, blurb: "Investigations and approvals" },
  { username: "manager", name: "Priya Sharma", role: "SOC Manager", icon: Users, blurb: "KPIs, workload, critical approvals" },
  { username: "auditor", name: "Vikram Nair", role: "Auditor", icon: ClipboardCheck, blurb: "Read-only decision trail" },
  { username: "admin", name: "Aarav Mehta", role: "SOC Admin", icon: UserCog, blurb: "Users, LLM providers, integrations" },
];

const AGENTS = ["Supervisor", "Triage", "Threat Intel", "Asset Context", "Investigation", "Response", "Reporting"];

export default function LoginPage() {
  const router = useRouter();
  const setSession = useAuth((s) => s.setSession);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/login/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, auth_type: "local" }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new ApiError(res.status, data.detail ?? "Login failed", data);
      setSession(data.access, data.refresh, data.user as User);
      router.replace(ROLE_HOME[(data.user as User).role]);
    } catch (err) {
      setError(err instanceof ApiError ? err : new Error("Cannot reach the SOC backend. Is it running?"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      <section className="relative hidden flex-col justify-between overflow-hidden border-r border-line bg-panel p-10 lg:flex">
        <div className="flex items-center gap-3">
          <Logo size={34} />
          <div>
            <div className="text-lg font-semibold">NEXUS-SOC</div>
            <div className="text-xs text-ink-3">Multi-agent Security Operations Center</div>
          </div>
        </div>
        <div className="max-w-lg">
          <h1 className="text-3xl font-semibold leading-tight tracking-tight">
            Seven AI agents investigate every alert.
            <span className="text-ink-3"> Analysts stay in command.</span>
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-ink-2">
            A Supervisor routes each case through triage, threat intelligence, asset context, investigation, response planning and
            reporting. Risky containment actions always wait for a human with the right role.
          </p>
          <div className="mt-8 flex flex-wrap gap-2">
            {AGENTS.map((a, i) => (
              <span key={a} className="flex items-center gap-1.5 rounded-full border border-line-strong bg-bg px-3 py-1 text-xs text-ink-2">
                <Bot className={cx("size-3.5", i === 0 ? "text-accent" : "text-ink-3")} />
                {a}
              </span>
            ))}
          </div>
        </div>
        <div className="text-xs text-ink-3">Runs online with DeepSeek, OpenAI or Gemini, and fully offline with the built-in engine.</div>
      </section>

      <section className="flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          <div className="mb-6 flex items-center gap-3 lg:hidden">
            <Logo />
            <span className="font-semibold">NEXUS-SOC</span>
          </div>
          <h2 className="text-xl font-semibold">Sign in</h2>
          <p className="mt-1 text-sm text-ink-3">Your role decides what you see and what you can approve.</p>

          <form onSubmit={submit} className="mt-6 space-y-4">
            <Field label="Username">
              <input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
            </Field>
            <Field label="Password">
              <input type="password" className={inputClass} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
            </Field>
            {error ? <ErrorBox error={error} /> : null}
            <Button type="submit" variant="primary" className="w-full" loading={loading} icon={<KeyRound className="size-4" />}>
              Sign in
            </Button>
          </form>

          <div className="mt-8">
            <div className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-3">Demo personas</div>
            <div className="grid gap-2">
              {DEMO.map((d) => (
                <button
                  key={d.username}
                  type="button"
                  onClick={() => {
                    setUsername(d.username);
                    setPassword(DEMO_PASSWORD);
                  }}
                  className={cx(
                    "flex items-center gap-3 rounded-md border px-3 py-2 text-left transition-colors",
                    username === d.username ? "border-accent bg-accent/10" : "border-line bg-panel hover:border-line-strong",
                  )}
                >
                  <d.icon className="size-4 text-ink-3" />
                  <div className="flex-1">
                    <div className="text-sm font-medium">
                      {d.name} <span className="text-ink-3">- {d.role}</span>
                    </div>
                    <div className="text-xs text-ink-3">{d.blurb}</div>
                  </div>
                  <code className="text-xs text-ink-3">{d.username}</code>
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
