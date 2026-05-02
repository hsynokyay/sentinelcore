"use client";

import { useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, Filter } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { DensityToggle } from "@/components/data/density-toggle";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
import { ErrorState } from "@/components/data/error-state";
import { ChangeSummaryStrip } from "@/components/security/change-summary-strip";
import { useRegisterCommands } from "@/components/layout/command-provider";
import type { DynamicCommand } from "@/components/layout/command-provider";
import { RisksTable } from "@/features/risks/risks-table";
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
  const [explicitProjectId, setExplicitProjectId] = useState<string>("");
  const projectId = explicitProjectId || projects[0]?.id || "";
  const [status, setStatus] = useState<StatusFilter>("active");

  // Register contextual commands — these appear in the palette only
  // while the /risks page is mounted. Selecting one changes the
  // status filter and the palette closes automatically.
  useRegisterCommands([
    {
      id: "risks-filter-active",
      label: "Filter: Active risks",
      group: "Context",
      icon: Filter,
      onSelect: () => setStatus("active"),
      keywords: ["active", "open"],
    },
    {
      id: "risks-filter-resolved",
      label: "Filter: Resolved risks",
      group: "Context",
      icon: Filter,
      onSelect: () => setStatus("user_resolved"),
      keywords: ["resolved", "closed"],
    },
    {
      id: "risks-filter-all",
      label: "Filter: All risks",
      group: "Context",
      icon: Filter,
      onSelect: () => setStatus("all"),
      keywords: ["all", "everything"],
    },
  ]);

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

  // Register loaded risks as jump targets in the command palette.
  // Typing "# sql" in the palette filters to risks matching "sql".
  const riskRouter = useRouter();
  const riskJumpCommands: DynamicCommand[] = useMemo(
    () =>
      (allRisksData?.risks ?? []).slice(0, 50).map((r) => ({
        id: `risk-jump-${r.id}`,
        label: r.title,
        group: "Risks",
        icon: AlertTriangle,
        onSelect: () => riskRouter.push(`/risks/${r.id}`),
        keywords: [r.severity, r.vuln_class.replace(/_/g, " "), `${r.risk_score}`],
      })),
    [allRisksData, riskRouter],
  );
  useRegisterCommands(riskJumpCommands);

  const risks = data?.risks ?? [];
  const isEmpty = !isLoading && risks.length === 0;

  return (
    <>
      <PageHeader
        title="Risks"
        description="Explainable risk clusters correlated from SAST, DAST, and attack surface."
        count={isLoading ? "—" : (allRisksData?.risks?.length ?? 0)}
        filters={
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
        }
        actions={<DensityToggle />}
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

      {isError ? (
        <ErrorState message="Failed to load risks" onRetry={() => refetch()} />
      ) : isEmpty ? (
        <EmptyStateBranded
          icon={AlertTriangle}
          title="No risks correlated yet"
          description="Risks appear after a SAST + DAST scan completes for this project."
        />
      ) : (
        <RisksTable
          data={risks}
          isLoading={isLoading}
        />
      )}
    </>
  );
}
