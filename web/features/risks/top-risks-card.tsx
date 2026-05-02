"use client";

import Link from "next/link";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { ChartContainer } from "@/components/security/chart-container";
import { MicroInsight } from "@/components/security/micro-insight";
import { useRisks } from "./hooks";

export function TopRisksCard({ projectId }: { projectId: string }) {
  const { data, isLoading } = useRisks({
    project_id: projectId,
    status: "active",
    limit: 5,
  });

  const risks = data?.risks ?? [];
  const criticalCount = risks.filter((r) => r.severity === "critical").length;

  const insightText =
    risks.length === 0
      ? "No active risks."
      : criticalCount > 0
        ? `${criticalCount} of top ${risks.length} are critical.`
        : `Top ${risks.length} risks — none critical.`;
  const insightTone =
    criticalCount > 0 ? "negative" : risks.length > 0 ? "neutral" : "positive";

  return (
    <ChartContainer
      title="Top Risks"
      insight={
        !isLoading && risks.length > 0 ? (
          <MicroInsight
            text={insightText}
            tone={insightTone as "negative" | "neutral" | "positive"}
          />
        ) : undefined
      }
      isLoading={isLoading}
      loadingHeight={200}
      actions={
        <Link
          href="/risks"
          className="text-xs text-muted-foreground hover:underline"
        >
          View all
        </Link>
      }
    >
      {risks.length === 0 && !isLoading ? (
        <p className="py-6 text-center text-sm text-muted-foreground">
          No active risks.
        </p>
      ) : (
        <ul className="space-y-1">
          {risks.map((r) => (
            <li key={r.id}>
              <Link
                href={`/risks/${r.id}`}
                className="flex items-center gap-3 rounded-md p-2 hover:bg-accent"
              >
                <span className="w-8 text-right text-base font-semibold tabular-nums">
                  {r.risk_score}
                </span>
                <SeverityBadge severity={r.severity} />
                <span className="flex-1 truncate text-sm">{r.title}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </ChartContainer>
  );
}
