"use client"

import { useMemo } from "react"
import { PageHeader } from "@/components/data/page-header"
import { ChangeSummaryStrip } from "@/components/security/change-summary-strip"
import { MicroInsight } from "@/components/security/micro-insight"
import { SeverityDistributionChart } from "@/features/risks/severity-distribution-chart"
import { TopRisksCard } from "@/features/risks/top-risks-card"
import { RuntimeConfirmedCard } from "@/features/dashboard/runtime-confirmed-card"
import { PublicExposureCard } from "@/features/dashboard/public-exposure-card"
import { useRisks } from "@/features/risks/hooks"
import { useScans } from "@/features/scans/hooks"
import { useProjectId } from "@/lib/workspace-context"
import { computeDashboardTiles } from "@/features/dashboard/dashboard-stats"

export default function DashboardPage() {
  const projectId = useProjectId()

  const { data: risksData, isLoading: risksLoading } = useRisks({
    project_id: projectId, status: "all", limit: 200,
  })
  const { data: scansData, isLoading: scansLoading } = useScans({ limit: 25 })

  const isLoading = risksLoading || scansLoading || !projectId

  const tiles = useMemo(
    () => computeDashboardTiles(risksData?.risks ?? [], scansData?.scans ?? []),
    [risksData, scansData]
  )

  const risks = risksData?.risks ?? []
  const activeCount = risks.filter((r) => r.status === "active").length
  const criticalCount = risks.filter(
    (r) => r.status === "active" && r.severity === "critical"
  ).length

  const insightText =
    activeCount === 0
      ? "No active risks. Your attack surface looks clean."
      : criticalCount > 0
        ? `${criticalCount} critical risk${criticalCount > 1 ? "s" : ""} need${
            criticalCount === 1 ? "s" : ""
          } attention across ${activeCount} active.`
        : `${activeCount} active risk${activeCount > 1 ? "s" : ""} — none critical.`
  const insightTone = (criticalCount > 0
    ? "negative"
    : activeCount > 0
      ? "neutral"
      : "positive") as "negative" | "neutral" | "positive"

  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" description="Security posture at a glance." />

      <section>
        {!isLoading && <MicroInsight text={insightText} tone={insightTone} />}
        <div className="mt-3">
          <ChangeSummaryStrip tiles={tiles} isLoading={isLoading} />
        </div>
      </section>

      <SeverityDistributionChart risks={risks} isLoading={isLoading} />

      <div className="grid gap-4 lg:grid-cols-3">
        {projectId && <TopRisksCard projectId={projectId} />}
        <RuntimeConfirmedCard risks={risks} isLoading={isLoading} />
        <PublicExposureCard risks={risks} isLoading={isLoading} />
      </div>
    </div>
  )
}
