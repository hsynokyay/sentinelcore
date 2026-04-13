"use client";

import { useState, useMemo } from "react";
import { PageHeader } from "@/components/data/page-header";
import { ErrorState } from "@/components/data/error-state";
import { ChangeSummaryStrip } from "@/components/security/change-summary-strip";
import { RisksTable } from "@/features/risks/risks-table";
import { RisksEmptyState } from "@/features/risks/risks-empty-state";
import { SeverityDistributionChart } from "@/features/risks/severity-distribution-chart";
import { useRisks } from "@/features/risks/hooks";
import { computeRiskSummaryTiles } from "@/features/risks/risk-stats";
import { useProjects } from "@/features/scans/hooks";
import type { RiskStatus } from "@/lib/types";

type StatusFilter = RiskStatus | "all";

const statusTabs: { id: StatusFilter; label: string }[] = [
  { id: "active", label: "Active" },
  { id: "user_resolved", label: "Resolved" },
  { id: "muted", label: "Muted" },
  { id: "auto_resolved", label: "Auto-resolved" },
  { id: "all", label: "All" },
];

export default function RisksPage() {
  const { data: projectsData } = useProjects();
  const projects = useMemo(() => projectsData?.projects ?? [], [projectsData]);
  // The project selector is "controlled if explicit, else default to
  // first available". Computed inline rather than via useEffect+setState
  // so we don't trip the React 19 `set-state-in-effect` lint rule, and
  // so the derived value reacts immediately to a new projects payload
  // without an extra render cycle.
  const [explicitProjectId, setExplicitProjectId] = useState<string>("");
  const projectId = explicitProjectId || projects[0]?.id || "";
  const [status, setStatus] = useState<StatusFilter>("active");

  const { data, isLoading, isError, refetch } = useRisks({
    project_id: projectId,
    status,
    limit: 50,
  });

  // Project-wide stats query — independent of the visible filter so the
  // ChangeSummaryStrip always shows the bird's-eye view, not whatever
  // the user has filtered the table down to. React Query dedupes both
  // calls by their unique queryKey.
  const { data: allRisksData, isLoading: isStatsLoading } = useRisks({
    project_id: projectId,
    status: "all",
    limit: 200,
  });

  const summaryTiles = useMemo(
    () => computeRiskSummaryTiles(allRisksData?.risks ?? []),
    [allRisksData],
  );

  return (
    <div>
      <PageHeader
        title="Risks"
        description="Explainable risk clusters correlated from SAST, DAST, and attack surface."
      />

      <div className="mb-4 space-y-4">
        <ChangeSummaryStrip
          tiles={summaryTiles}
          isLoading={isStatsLoading || !projectId}
        />
        {/* Severity distribution chart — complements the strip by
            showing proportional shares of the active surface, where
            the strip shows absolute counts. Uses the same all-status
            project-wide query so the picture is the bird's-eye view. */}
        <SeverityDistributionChart
          risks={allRisksData?.risks ?? []}
          isLoading={isStatsLoading || !projectId}
        />
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <select
          className="rounded border bg-background px-3 py-1.5 text-sm"
          value={projectId}
          onChange={(e) => setExplicitProjectId(e.target.value)}
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.display_name || p.name}
            </option>
          ))}
        </select>

        <div className="flex gap-1 rounded-lg border bg-background p-1">
          {statusTabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setStatus(t.id)}
              className={`rounded-md px-3 py-1 text-sm ${
                status === t.id
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {isError ? (
        <ErrorState message="Failed to load risks" onRetry={() => refetch()} />
      ) : (
        <RisksTable
          data={data?.risks ?? []}
          isLoading={isLoading}
          emptyContent={
            <RisksEmptyState
              totalRisks={allRisksData?.risks?.length ?? 0}
              currentFilter={status}
              onClearFilter={() => setStatus("all")}
            />
          }
        />
      )}
    </div>
  );
}
