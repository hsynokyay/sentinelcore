"use client"

import { useMemo } from "react"
import { AlertTriangle, Activity, Shield, ShieldCheck } from "lucide-react"
import { PageHeader } from "@/components/data/page-header"
import { ChangeSummaryStrip } from "@/components/security/change-summary-strip"
import { MicroInsight } from "@/components/security/micro-insight"
import { HeroStat } from "@/components/security/hero-stat"
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

  const last7DaysSparkline = useMemo(() => {
    const buckets = Array.from({ length: 7 }, (_, i) => {
      const day = new Date()
      day.setHours(0, 0, 0, 0)
      day.setDate(day.getDate() - (6 - i))
      const next = new Date(day)
      next.setDate(next.getDate() + 1)
      return risks.filter((r) => {
        const t = new Date(r.first_seen_at ?? 0).getTime()
        return t >= day.getTime() && t < next.getTime()
      }).length
    })
    return buckets
  }, [risks])

  const completedScansLast7 = useMemo(() => {
    const since = Date.now() - 7 * 24 * 60 * 60 * 1000
    return (scansData?.scans ?? []).filter(
      (s) => s.status === "completed" && new Date(s.created_at).getTime() >= since
    ).length
  }, [scansData])

  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" description="Security posture at a glance." />

      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <HeroStat
          label="Active risks"
          value={activeCount}
          icon={<AlertTriangle className="size-3.5" />}
          delta={
            criticalCount > 0
              ? { text: `${criticalCount} critical`, tone: "negative" }
              : { text: "no critical", tone: "positive" }
          }
          sparkline={last7DaysSparkline}
          tone={criticalCount > 0 ? "critical" : "brand"}
        />
        <HeroStat
          label="Critical"
          value={criticalCount}
          icon={<ShieldCheck className="size-3.5" />}
          tone={criticalCount > 0 ? "critical" : "success"}
        />
        <HeroStat
          label="Scans (7d)"
          value={completedScansLast7}
          icon={<Activity className="size-3.5" />}
          tone="brand"
        />
        <HeroStat
          label="Findings tracked"
          value={risks.reduce((s, r) => s + (r.finding_count ?? 0), 0)}
          icon={<Shield className="size-3.5" />}
          tone="brand"
        />
      </section>

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
