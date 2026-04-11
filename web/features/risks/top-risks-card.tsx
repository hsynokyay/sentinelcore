"use client";

import Link from "next/link";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { useRisks } from "./hooks";

export function TopRisksCard({ projectId }: { projectId: string }) {
  const { data, isLoading } = useRisks({
    project_id: projectId,
    status: "active",
    limit: 5,
  });
  return (
    <div className="rounded-lg border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="font-semibold">Top Risks</h2>
        <Link href="/risks" className="text-xs text-muted-foreground hover:underline">
          View all
        </Link>
      </div>
      {isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
      {!isLoading && (data?.risks.length ?? 0) === 0 && (
        <div className="text-sm text-muted-foreground">No active risks.</div>
      )}
      <ul className="space-y-2">
        {data?.risks.map((r) => (
          <li key={r.id}>
            <Link
              href={`/risks/${r.id}`}
              className="flex items-center gap-3 rounded-md p-2 hover:bg-accent"
            >
              <div className="w-10 text-right text-lg font-semibold tabular-nums">
                {r.risk_score}
              </div>
              <SeverityBadge severity={r.severity} />
              <div className="flex-1 truncate text-sm">{r.title}</div>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
