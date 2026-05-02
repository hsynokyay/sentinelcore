"use client";

import { useState, useMemo } from "react";
import { PageHeader } from "@/components/data/page-header";
import { ChangeSummaryStrip } from "@/components/security/change-summary-strip";
import { MicroInsight } from "@/components/security/micro-insight";
import { SeverityDistributionChart } from "@/features/risks/severity-distribution-chart";
import { TopRisksCard } from "@/features/risks/top-risks-card";
import { RuntimeConfirmedCard } from "@/features/dashboard/runtime-confirmed-card";
import { PublicExposureCard } from "@/features/dashboard/public-exposure-card";
import { useRisks } from "@/features/risks/hooks";
import { useScans } from "@/features/scans/hooks";
import { useProjects } from "@/features/scans/hooks";
import { computeDashboardTiles } from "@/features/dashboard/dashboard-stats";

export default function DashboardPage() {
  const { data: projectsData } = useProjects();
  const projects = useMemo(
    () => projectsData?.projects ?? [],
    [projectsData],
  );
  const [explicitProjectId, setExplicitProjectId] = useState<string>("");
  const projectId = explicitProjectId || projects[0]?.id || "";

  // Fetch all risks (any status) and recent scans for the narrative strip.
  const { data: risksData, isLoading: risksLoading } = useRisks({
    project_id: projectId,
    status: "all",
    limit: 200,
  });
  const { data: scansData, isLoading: scansLoading } = useScans({
    limit: 25,
  });

  const isLoading = risksLoading || scansLoading || !projectId;

  const tiles = useMemo(
    () =>
      computeDashboardTiles(
        risksData?.risks ?? [],
        scansData?.scans ?? [],
      ),
    [risksData, scansData],
  );

  // Compute a single-sentence narrative insight for the strip header.
  const risks = risksData?.risks ?? [];
  const activeCount = risks.filter((r) => r.status === "active").length;
  const criticalCount = risks.filter(
    (r) => r.status === "active" && r.severity === "critical",
  ).length;

  const insightText =
    activeCount === 0
      ? "No active risks. Your attack surface looks clean."
      : criticalCount > 0
        ? `${criticalCount} critical risk${criticalCount > 1 ? "s" : ""} need${criticalCount === 1 ? "s" : ""} attention across ${activeCount} active.`
        : `${activeCount} active risk${activeCount > 1 ? "s" : ""} — none critical.`;
  const insightTone =
    criticalCount > 0 ? "negative" : activeCount > 0 ? "neutral" : "positive";

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Security posture at a glance."
      />

      {/* Project selector */}
      <div className="mb-4 max-w-xs">
        <select
          className="w-full rounded border bg-background px-3 py-1.5 text-sm"
          value={projectId}
          onChange={(e) => setExplicitProjectId(e.target.value)}
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.display_name || p.name}
            </option>
          ))}
        </select>
      </div>

      {/* Narrative layer: insight sentence → change summary tiles */}
      <div className="mb-6 space-y-3">
        {!isLoading && (
          <MicroInsight
            text={insightText}
            tone={insightTone as "negative" | "neutral" | "positive"}
          />
        )}
        <ChangeSummaryStrip tiles={tiles} isLoading={isLoading} />
      </div>

      {/* Visual breakdowns — 2×2 grid on lg+, stacked on mobile */}
      <div className="grid gap-6 lg:grid-cols-2">
        <SeverityDistributionChart
          risks={risksData?.risks ?? []}
          isLoading={isLoading}
        />
        {projectId && <TopRisksCard projectId={projectId} />}
        <RuntimeConfirmedCard
          risks={risksData?.risks ?? []}
          isLoading={isLoading}
        />
        <PublicExposureCard
          risks={risksData?.risks ?? []}
          isLoading={isLoading}
        />
      </div>
    </div>
  );
}
