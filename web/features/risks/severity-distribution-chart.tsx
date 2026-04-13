"use client";

import { ChartContainer } from "@/components/security/chart-container";
import { MicroInsight } from "@/components/security/micro-insight";
import { InsightTooltip } from "@/components/security/insight-tooltip";
import { severityFillVar } from "@/lib/security/intensity";
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
 * SeverityDistributionChart — a hand-rolled SVG stacked horizontal
 * bar that shows the proportion of each severity band in the active
 * risk surface. Wraps everything in ChartContainer so it inherits
 * the standard chrome, leads with a MicroInsight (the conclusion),
 * and exposes per-segment InsightTooltips on hover.
 *
 * Why hand-rolled instead of Recharts:
 *  - We have one chart, this codebase has zero charts today, and
 *    Recharts is a chunky dependency for one consumer.
 *  - The visual is dead simple — five severity-coloured rectangles
 *    in a row with proportional widths. SVG handles that in 30 lines.
 *  - Severity colours come from the existing oklch tokens, so the
 *    chart inherits the design system without a translation layer.
 *
 * Empty state: when there are zero active risks the bar shows a
 * single full-width track in the contrib-track colour, the insight
 * reads "No active risks", and the legend renders as zeros. The
 * empty case never throws or produces an empty-string SVG.
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
      footer={
        <ul className="flex flex-wrap items-center gap-x-4 gap-y-1">
          {buckets.map((b) => (
            <li
              key={b.severity}
              className="flex items-center gap-1.5 tabular-nums"
            >
              <span
                aria-hidden="true"
                className="block h-2 w-2 rounded-sm"
                style={{ backgroundColor: severityFillVar(b.severity) }}
              />
              <span>
                {SEVERITY_LABEL[b.severity]}{" "}
                <span className="text-foreground font-semibold">{b.count}</span>{" "}
                <span className="opacity-60">({b.percent}%)</span>
              </span>
            </li>
          ))}
        </ul>
      }
    >
      <DistributionBar buckets={buckets} total={total} />
    </ChartContainer>
  );
}

/**
 * The actual horizontal bar. Pulled out so the parent component reads
 * as a straightforward composition of (insight, bar, footer).
 *
 * Each segment is a flex item with width proportional to its bucket
 * percentage, wrapped in an InsightTooltip for hover details. Zero-
 * count segments are filtered out before rendering so the bar doesn't
 * grow holes. Segments are placed in SEVERITY_ORDER (critical first),
 * so the eye-catching colours sit on the left edge regardless of the
 * actual proportions.
 *
 * Why flex instead of computed offsets: flex children naturally lay
 * out left-to-right with no positioning math. Removing the offset
 * pass also sidesteps React 19's `react-hooks/immutability` rule
 * against mutating render-scoped variables.
 */
function DistributionBar({
  buckets,
  total,
}: {
  buckets: SegmentBucket[];
  total: number;
}) {
  // Empty state: render a single muted track so the bar still
  // occupies its slot and the layout doesn't collapse.
  if (total === 0) {
    return (
      <div
        className="h-9 w-full rounded-md bg-[var(--contrib-track)]"
        aria-label="No active risks"
      />
    );
  }

  const visibleSegments = buckets.filter((b) => b.count > 0);

  return (
    <div
      role="img"
      aria-label={`Severity distribution: ${visibleSegments
        .map((b) => `${SEVERITY_LABEL[b.severity]} ${b.count}`)
        .join(", ")}`}
      className="flex h-9 w-full overflow-hidden rounded-md bg-[var(--contrib-track)]"
    >
      {visibleSegments.map((seg) => (
        <InsightTooltip
          key={seg.severity}
          content={
            <div className="space-y-0.5">
              <p className="font-semibold text-foreground">
                {SEVERITY_LABEL[seg.severity]} · {seg.count}{" "}
                {seg.count === 1 ? "risk" : "risks"}
              </p>
              <p className="text-muted-foreground">
                {seg.percent}% of {total} active
              </p>
            </div>
          }
        >
          <div
            className="h-full transition-[filter] hover:brightness-110 cursor-default"
            style={{
              width: `${seg.fullPercent}%`,
              backgroundColor: severityFillVar(seg.severity),
            }}
            data-severity={seg.severity}
            data-count={seg.count}
          />
        </InsightTooltip>
      ))}
    </div>
  );
}
