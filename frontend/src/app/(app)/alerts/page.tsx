"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Card, cx, inputClass, PageHeader, SeverityBadge, Spinner, Table } from "@/components/ui";
import { get } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Alert, Paginated } from "@/lib/types";

export default function AlertsPage() {
  const [severity, setSeverity] = useState("");
  const [search, setSearch] = useState("");
  const q = useQuery({
    queryKey: ["alerts", "list", severity, search],
    queryFn: () => get<Paginated<Alert>>("/alerts", { page_size: 100, ordering: "-created_at", severity, search }),
    refetchInterval: 30_000,
  });
  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader title="Alerts" subtitle="Raw detections from SIEM, EDR, email and cloud sources. Related alerts are correlated into cases automatically." />
      <Card bodyClassName="p-0">
        <div className="flex flex-wrap gap-2 border-b border-line p-3">
          <input className={cx(inputClass, "max-w-sm")} placeholder="Search alerts" value={search} onChange={(e) => setSearch(e.target.value)} />
          <select className={cx(inputClass, "w-auto")} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">Any severity</option>
            {["Critical", "High", "Medium", "Low"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
        {q.isLoading ? (
          <Spinner />
        ) : (
          <Table head={["Alert", "Source", "Severity", "ATT&CK", "Case", "First seen"]}>
            {(q.data?.results ?? []).map((a) => (
              <tr key={a.id} className="hover:bg-panel-2/60">
                <td className="max-w-[420px] px-3 py-2.5">
                  <div className="truncate font-medium">{a.title}</div>
                  <div className="truncate text-xs text-ink-3">{a.rule_name}</div>
                </td>
                <td className="whitespace-nowrap px-3 py-2.5 text-xs text-ink-3">
                  {a.product_vendor} {a.product_name}
                </td>
                <td className="px-3 py-2.5">
                  <SeverityBadge value={a.severity} />
                </td>
                <td className="px-3 py-2.5 text-xs">{a.technique || "-"}</td>
                <td className="whitespace-nowrap px-3 py-2.5">
                  <Link href={`/cases/${a.case}`} className="font-mono text-xs text-[#8fbcf3] hover:underline">
                    {a.case_readable_id?.toUpperCase()}
                  </Link>
                </td>
                <td className="whitespace-nowrap px-3 py-2.5 text-xs text-ink-3">{formatDateTime(a.first_seen_time)}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
