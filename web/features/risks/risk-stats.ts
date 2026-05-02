import type { RiskCluster } from "@/lib/types";
import type { SummaryTile } from "@/components/security/change-summary-strip";

/** Time window used for "this week" deltas. Kept as a single constant
 *  so the wording in the strip and the math here can never drift. */
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Compute the four canonical risk-page summary stats from a list of
 * risks. The list is expected to be the project-wide `status='all'`
 * snapshot, NOT the visible filtered table — the strip is the bird's-
 * eye view, the table is the focused view.
 *
 * "This week" = first_seen_at within the last 7 days. Computed entirely
 * client-side from the existing `first_seen_at` field, so no backend
 * change is required to ship the strip. If a server-side stats endpoint
 * lands later, this helper can be replaced without touching the strip.
 */
export function computeRiskSummaryTiles(
  risks: RiskCluster[],
): SummaryTile[] {
  const cutoff = Date.now() - SEVEN_DAYS_MS;
  const isNew = (r: RiskCluster) =>
    new Date(r.first_seen_at).getTime() >= cutoff;

  // The "active" subset is the canonical denominator for the segment
  // tiles — we don't want closed-but-still-existing risks counted in
  // the "CRITICAL" tile, since they no longer need attention.
  const active = risks.filter((r) => r.status === "active");
  const critical = active.filter((r) => r.severity === "critical");
  const high = active.filter((r) => r.severity === "high");

  // ADDED THIS WEEK is computed against the FULL list (any status), so
  // a freshly-discovered risk that gets auto-resolved an hour later
  // still counts — the operator should still see it surfaced.
  const newThisWeek = risks.filter(isNew);

  return [
    {
      label: "Active",
      value: active.length,
      delta: {
        value: active.filter(isNew).length,
        label: "new this week",
        // More active risks = bad news.
        polarity: "bad-when-positive",
      },
    },
    {
      label: "Critical",
      value: critical.length,
      delta: {
        value: critical.filter(isNew).length,
        label: "new this week",
        polarity: "bad-when-positive",
      },
      emphasis: "critical",
    },
    {
      label: "High",
      value: high.length,
      delta: {
        value: high.filter(isNew).length,
        label: "new this week",
        polarity: "bad-when-positive",
      },
      emphasis: "high",
    },
    {
      // No delta on this tile — the value IS the time-bound count.
      // Adding "+5 this week" next to "5" would be tautological.
      label: "Added this week",
      value: newThisWeek.length,
    },
  ];
}
