"use client";

import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import ProposalCard from "@/components/agents/ProposalCard";
import { Card, Empty, PageHeader, Spinner, Tabs } from "@/components/ui";
import { useProposals } from "@/lib/queries";

type Status = "Pending" | "Executed" | "Rejected" | "";

export default function ApprovalsPage() {
  const [status, setStatus] = useState<Status>("Pending");
  const [risk, setRisk] = useState("");
  const q = useProposals({ status, risk_level: risk });

  return (
    <div className="mx-auto max-w-[1100px]">
      <PageHeader
        title="Approvals center"
        subtitle="Containment actions proposed by the Response Agent. Low-risk actions run automatically; everything else needs the right role."
      />
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <Tabs<Status>
          value={status}
          onChange={setStatus}
          tabs={[
            { key: "Pending", label: "Pending" },
            { key: "Executed", label: "Executed" },
            { key: "Rejected", label: "Rejected" },
            { key: "", label: "All" },
          ]}
        />
        <select className="rounded-md border border-line-strong bg-bg px-2 py-1.5 text-sm" value={risk} onChange={(e) => setRisk(e.target.value)}>
          <option value="">Any risk</option>
          {["Critical", "High", "Medium", "Low"].map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
      </div>
      <Card bodyClassName="p-4">
        {q.isLoading ? (
          <Spinner />
        ) : q.data?.results.length ? (
          <div className="grid gap-3 lg:grid-cols-2">
            {q.data.results.map((p) => (
              <ProposalCard key={p.id} proposal={p} showCase />
            ))}
          </div>
        ) : (
          <Empty title={status === "Pending" ? "No actions waiting for approval" : "Nothing here yet"} icon={<ShieldCheck className="size-8" />} />
        )}
      </Card>
      <p className="mt-3 text-xs text-ink-3">
        Approval policy: Medium/High risk needs a Tier-2 Responder or SOC Manager; Critical risk (or any action on a business-critical asset) needs a SOC
        Manager. Connectors are simulated in this environment.
      </p>
    </div>
  );
}
