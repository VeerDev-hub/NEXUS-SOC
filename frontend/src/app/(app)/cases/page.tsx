"use client";

import { useState } from "react";
import { Search } from "lucide-react";
import CaseTable from "@/components/CaseTable";
import { Card, cx, ErrorBox, inputClass, PageHeader, Spinner } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { useCases } from "@/lib/queries";

const STATUS = ["", "New", "In Progress", "On Hold", "Resolved", "Closed"];
const SEVERITY = ["", "Critical", "High", "Medium", "Low"];

export default function CasesPage() {
  const user = useAuth((s) => s.user);
  const [tier, setTier] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [mine, setMine] = useState(false);
  const [search, setSearch] = useState("");

  const q = useCases({ tier, status, severity, search, assignee: mine ? user?.id : undefined }, 30_000);

  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader title="Cases" subtitle="Every case is triaged by the AI agent team before it reaches an analyst." />
      <Card bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
          <div className="relative min-w-[220px] flex-1">
            <Search className="absolute left-2.5 top-2.5 size-4 text-ink-3" />
            <input className={cx(inputClass, "pl-8")} placeholder="Search title, ID, description" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <select className={cx(inputClass, "w-auto")} value={tier} onChange={(e) => setTier(e.target.value)}>
            <option value="">All queues</option>
            <option value="L1">Tier-1 queue</option>
            <option value="L2">Tier-2 queue</option>
          </select>
          <select className={cx(inputClass, "w-auto")} value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUS.map((s) => (
              <option key={s} value={s}>
                {s || "Any status"}
              </option>
            ))}
          </select>
          <select className={cx(inputClass, "w-auto")} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITY.map((s) => (
              <option key={s} value={s}>
                {s || "Any severity"}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-2 px-2 text-sm text-ink-2">
            <input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} /> Assigned to me
          </label>
        </div>
        {q.isLoading ? <Spinner /> : q.error ? <div className="p-4"><ErrorBox error={q.error} /></div> : <CaseTable cases={q.data!.results} emptyTitle="No cases match these filters" />}
        {q.data && <div className="border-t border-line px-3 py-2 text-xs text-ink-3">{q.data.count} case(s)</div>}
      </Card>
    </div>
  );
}
