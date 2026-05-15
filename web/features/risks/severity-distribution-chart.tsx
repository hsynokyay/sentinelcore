"use client";

import { ChartContainer } from "@/components/security/chart-container";
import { MicroInsight } from "@/components/security/micro-insight";
import { StackedBar } from "@/components/security/stacked-bar";
import { Badge } from "@/components/ui/badge";
import type { RiskCluster, RiskSeverity } from "@/lib/types";

/**
 * Order matters here — the bar segments render in this order from
 * left (highest priority) to right (lowest), so the eye lands on
 * critical first regardless of the segment widths.
 */
const SEVERITY_ORDER: RiskSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const SEVERITY_LABEL: Record<RiskSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

interface SegmentBucket {
  severity: RiskSeverity;
  count: number;
  /** Percentage of the active total. Pre-rounded for display, full
   *  precision used for the SVG width. */
  percent: number;
  fullPercent: number;
}

/**
 * Compute the severity distribution from a list of risks. Filters to
 * `status === "active"` because the chart shows the *current attack
 * surface*, not the historical ledger. Returns one bucket per severity
 * band even when count is 0 — the chart needs every band to render
 * the legend consistently.
 */
function buildBuckets(risks: RiskCluster[]): {
  total: number;
  buckets: SegmentBucket[];
} {
  const active = risks.filter((r) => r.status === "active");
  const total = active.length;

  const buckets = SEVERITY_ORDER.map<SegmentBucket>((severity) => {
    const count = active.filter((r) => r.severity === severity).length;
    const fullPercent = total > 0 ? (count / total) * 100 : 0;
    return {
      severity,
      count,
      fullPercent,
      percent: Math.round(fullPercent),
    };
  });

  return { total, buckets };
}

/**
 * Build the headline insight for the chart. Tries three rules in
 * priority order, falling back to a generic count statement.
 *
 *  1. If critical + high together account for >= 40% of the surface,
 *     state it (clear "elevated risk" signal).
 *  2. If a single severity dominates (>= 60%), state it.
 *  3. Otherwise, state the headline counts.
 *
 * The result is wrapped in `tone` so the MicroInsight colours itself
 * appropriately — high-criticals get the negative tone, balanced
 * distributions get neutral.
 */
function buildInsight(
  total: number,
  buckets: SegmentBucket[],
): { text: string; tone: "negative" | "warning" | "neutral" } {
  if (total === 0) {
    return { text: "No active risks.", tone: "neutral" };
  }

  const critical = buckets.find((b) => b.severity === "critical")!;
  const high = buckets.find((b) => b.severity === "high")!;
  const elevatedShare = critical.fullPercent + high.fullPercent;

  if (elevatedShare >= 40) {
    return {
      text: `${critical.count} critical and ${high.count} high account for ${Math.round(elevatedShare)}% of the active surface.`,
      tone: "negative",
    };
  }

  // Find the dominant severity (>= 60%).
  const dominant = buckets.find((b) => b.fullPercent >= 60);
  if (dominant) {
    return {
      text: `${SEVERITY_LABEL[dominant.severity]} severity dominates — ${dominant.count} of ${total} (${dominant.percent}%) active risks.`,
      tone: dominant.severity === "critical" || dominant.severity === "high" ? "negative" : "warning",
    };
  }

  return {
    text: `${total} active risks across ${buckets.filter((b) => b.count > 0).length} severity bands.`,
    tone: "neutral",
  };
}

/**
 * SeverityDistributionChart — renders a StackedBar showing the
 * proportion of each severity band in the active risk surface.
 * Wraps everything in ChartContainer so it inherits the standard
 * chrome, leads with a MicroInsight (the conclusion), and shows a
 * per-severity breakdown list below the bar.
 */
export function SeverityDistributionChart({
  risks,
  isLoading = false,
}: {
  risks: RiskCluster[];
  isLoading?: boolean;
}) {
  const { total, buckets } = buildBuckets(risks);
  const insight = buildInsight(total, buckets);

  return (
    <ChartContainer
      title="Severity distribution"
      insight={<MicroInsight text={insight.text} tone={insight.tone} />}
      isLoading={isLoading}
      loadingHeight={36}
    >
      <StackedBar segments={buckets} height={10} />
      <ul className="mt-4 grid grid-cols-2 gap-y-2 gap-x-6">
        {buckets.map((s) => (
          <li key={s.severity} className="flex items-center justify-between text-body-sm">
            <Badge variant="severity" tone={s.severity}>{SEVERITY_LABEL[s.severity]}</Badge>
            <span className="tabular-nums text-muted-foreground">{s.count}</span>
          </li>
        ))}
      </ul>
    </ChartContainer>
  );
}
