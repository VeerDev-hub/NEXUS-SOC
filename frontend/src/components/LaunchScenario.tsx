"use client";

import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Cloud, KeyRound, Mail, Radar, Skull, Zap } from "lucide-react";
import { get, post } from "@/lib/api";
import { can, useAuth } from "@/lib/auth";
import { toast } from "@/lib/toast";
import { Button, cx, Modal } from "./ui";

interface Scenario {
  key: string;
  label: string;
  description: string;
  expect: string;
}

const ICONS: Record<string, typeof Zap> = {
  ransomware: Skull,
  phishing: Mail,
  cloud_privesc: Cloud,
  vpn_bruteforce: KeyRound,
  authorized_scan: Radar,
};

export default function LaunchScenario() {
  const user = useAuth((s) => s.user);
  const router = useRouter();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: () => get<Scenario[]>("/demo/scenarios"), enabled: open });
  const launch = useMutation({
    mutationFn: (key: string) => post<{ case_pk: string; case_id: string }>("/demo/scenarios", { key }),
    onSuccess: (res) => {
      toast(`${res.case_id.toUpperCase()} created. The agent team is picking it up.`, "info");
      qc.invalidateQueries({ queryKey: ["cases"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
      setOpen(false);
      router.push(`/cases/${res.case_pk}`);
    },
    onError: (e: Error) => toast(e.message, "error"),
  });

  if (!can(user, "agents.run")) return null;
  return (
    <>
      <Button variant="primary" icon={<Zap className="size-4" />} onClick={() => setOpen(true)}>
        Launch attack scenario
      </Button>
      <Modal open={open} onClose={() => setOpen(false)} title="Simulate an incident" wide>
        <p className="mb-3 text-sm text-ink-3">
          Generates raw security events and sends them through the detection modules, exactly like a live SIEM feed. You will jump straight to
          the case to watch the agents work.
        </p>
        <div className="grid gap-2">
          {(scenarios.data ?? []).map((s) => {
            const Icon = ICONS[s.key] ?? Zap;
            return (
              <button
                key={s.key}
                disabled={launch.isPending}
                onClick={() => launch.mutate(s.key)}
                className={cx(
                  "flex items-start gap-3 rounded-md border border-line bg-panel-2 p-3 text-left transition-colors hover:border-accent disabled:opacity-60",
                  launch.isPending && launch.variables === s.key && "border-accent",
                )}
              >
                <Icon className="mt-0.5 size-5 shrink-0 text-accent" />
                <div className="flex-1">
                  <div className="text-sm font-medium">{s.label}</div>
                  <div className="text-xs text-ink-3">{s.description}</div>
                </div>
                <div className="max-w-[180px] text-right text-[11px] text-ink-3">{s.expect}</div>
              </button>
            );
          })}
        </div>
      </Modal>
    </>
  );
}
