import type { RiskCluster, RiskSeverity, Scan } from "@/lib/types";
import type {
  SummaryTile,
  BreakdownCaption,
  TopClassCaption,
} from "@/components/security/change-summary-strip";

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

const SEVERITY_ORDER: RiskSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

function formatFreshness(dateStr: string | null | undefined): string {
  if (!dateStr) return "Never";
  const d = new Date(dateStr);
  const diffMs = Date.now() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
}

/**
 * Build a severity-breakdown caption from a risk list. Returns segments
 * ordered by the canonical severity order so the mini-bar reads
 * critical → info left to right.
 */
function buildBreakdown(risks: RiskCluster[]): BreakdownCaption {
  const counts: Record<RiskSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const r of risks) counts[r.severity]++;
  return {
    mode: "breakdown",
    segments: SEVERITY_ORDER.map((sev) => ({
      severity: sev,
      count: counts[sev],
    })),
  };
}

/**
 * Build a top-class caption from a risk list. Finds the most common
 * vuln_class and reports it as "SQL injection · 4 of 7".
 */
function buildTopClass(risks: RiskCluster[]): TopClassCaption | undefined {
  if (risks.length === 0) return undefined;
  const freq: Record<string, number> = {};
  for (const r of risks) {
    const cls = r.vuln_class.replace(/_/g, " ");
    freq[cls] = (freq[cls] ?? 0) + 1;
  }
  const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
  const [topClass, topCount] = sorted[0];
  return {
    mode: "top-class",
    className: topClass.charAt(0).toUpperCase() + topClass.slice(1),
    share: `${topCount} of ${risks.length}`,
  };
}

/**
 * Compute the 6-tile narrative strip for the dashboard.
 *
 * Tile captions use three modes to tell a richer story:
 *
 *  1. **New risks**      — top-class caption ("Mostly SQL injection · 4 of 7")
 *  2. **Resolved**       — delta caption (good-when-positive, green)
 *  3. **Runtime confirmed** — delta caption (bad-when-positive, red)
 *  4. **Public exposure** — delta caption (bad-when-positive, red)
 *  5. **Active risks**   — breakdown caption (mini severity bar + top 2 counts)
 *  6. **Last scan**      — no caption (the value IS the freshness)
 */
export function computeDashboardTiles(
  risks: RiskCluster[],
  scans: Scan[],
): SummaryTile[] {
  const cutoff = Date.now() - SEVEN_DAYS_MS;
  const isRecent = (dateStr: string) =>
    new Date(dateStr).getTime() >= cutoff;

  const active = risks.filter((r) => r.status === "active");
  const newThisWeek = risks.filter((r) => isRecent(r.first_seen_at));
  const resolvedThisWeek = risks.filter(
    (r) => r.status === "user_resolved",
  );
  const runtimeThisWeek = newThisWeek.filter((r) =>
    r.top_reasons?.some(
      (reason) =>
        reason.code?.toLowerCase().includes("runtime") ||
        reason.label?.toLowerCase().includes("runtime"),
    ),
  );
  const publicThisWeek = newThisWeek.filter(
    (r) => r.exposure === "public" || r.exposure === "both",
  );

  const completed = scans
    .filter((s) => s.status === "completed" && s.finished_at)
    .sort(
      (a, b) =>
        new Date(b.finished_at!).getTime() -
        new Date(a.finished_at!).getTime(),
    );
  const lastScan = completed[0];

  // Build rich captions
  const newTopClass = buildTopClass(newThisWeek);
  const activeBreakdown = buildBreakdown(active);

  return [
    {
      label: "New risks",
      value: newThisWeek.length,
      caption: newTopClass ?? {
        mode: "delta",
        value: newThisWeek.length,
        label: "this week",
        polarity: "bad-when-positive",
      },
      emphasis: newThisWeek.some((r) => r.severity === "critical")
        ? "critical"
        : undefined,
    },
    {
      label: "Resolved",
      value: resolvedThisWeek.length,
      delta: {
        value: resolvedThisWeek.length,
        label: "closed",
        polarity: "good-when-positive",
      },
    },
    {
      label: "Runtime confirmed",
      value: runtimeThisWeek.length,
      delta: {
        value: runtimeThisWeek.length,
        label: "this week",
        polarity: "bad-when-positive",
      },
    },
    {
      label: "Public exposure",
      value: publicThisWeek.length,
      delta: {
        value: publicThisWeek.length,
        label: "this week",
        polarity: "bad-when-positive",
      },
    },
    {
      label: "Active risks",
      value: active.length,
      caption: activeBreakdown,
      emphasis: active.some((r) => r.severity === "critical")
        ? "critical"
        : active.some((r) => r.severity === "high")
          ? "high"
          : undefined,
    },
    {
      label: "Last scan",
      value: formatFreshness(lastScan?.finished_at),
    },
  ];
}
