"use client";

import { ChartContainer } from "@/components/security/chart-container";
import { MicroInsight } from "@/components/security/micro-insight";
import { InsightTooltip } from "@/components/security/insight-tooltip";
import type { RiskCluster, RiskExposure } from "@/lib/types";

const EXPOSURE_ORDER: RiskExposure[] = [
  "public",
  "both",
  "authenticated",
  "unknown",
];

const EXPOSURE_LABEL: Record<RiskExposure, string> = {
  public: "Public",
  both: "Public + auth",
  authenticated: "Authenticated",
  unknown: "Unknown",
};

const EXPOSURE_COLOR: Record<RiskExposure, string> = {
  public: "var(--severity-critical)",
  both: "var(--severity-high)",
  authenticated: "var(--severity-medium)",
  unknown: "var(--contrib-base)",
};

/**
 * PublicExposureCard — shows the proportion of active risks by their
 * exposure level. Public-facing risks are the highest-priority
 * remediation targets because they're reachable by any attacker.
 */
export function PublicExposureCard({
  risks,
  isLoading = false,
}: {
  risks: RiskCluster[];
  isLoading?: boolean;
}) {
  const active = risks.filter((r) => r.status === "active");
  const buckets = EXPOSURE_ORDER.map((exp) => ({
    exposure: exp,
    count: active.filter((r) => r.exposure === exp).length,
  }));
  const publicCount = buckets
    .filter((b) => b.exposure === "public" || b.exposure === "both")
    .reduce((sum, b) => sum + b.count, 0);
  const pct =
    active.length > 0
      ? Math.round((publicCount / active.length) * 100)
      : 0;

  const insightText =
    active.length === 0
      ? "No active risks."
      : publicCount === 0
        ? "No publicly exposed risks."
        : `${publicCount} of ${active.length} active risks (${pct}%) are publicly reachable.`;
  const insightTone =
    publicCount === 0
      ? "positive"
      : pct >= 50
        ? "negative"
        : "warning";

  return (
    <ChartContainer
      title="Exposure breakdown"
      insight={
        !isLoading ? (
          <MicroInsight text={insightText} tone={insightTone} />
        ) : undefined
      }
      isLoading={isLoading}
      loadingHeight={36}
    >
      {active.length === 0 ? (
        <p className="py-4 text-center text-xs text-muted-foreground">
          No active risks.
        </p>
      ) : (
        <div className="space-y-2">
          <div
            className="flex h-8 w-full overflow-hidden rounded-md bg-[var(--contrib-track)]"
            role="img"
            aria-label={buckets
              .filter((b) => b.count > 0)
              .map((b) => `${EXPOSURE_LABEL[b.exposure]} ${b.count}`)
              .join(", ")}
          >
            {buckets
              .filter((b) => b.count > 0)
              .map((b) => (
                <InsightTooltip
                  key={b.exposure}
                  content={
                    <p className="font-semibold">
                      {EXPOSURE_LABEL[b.exposure]} · {b.count}{" "}
                      {b.count === 1 ? "risk" : "risks"}
                    </p>
                  }
                  footer={
                    b.exposure === "public" ? (
                      <MicroInsight
                        text="Reachable by any attacker — highest priority."
                        tone="negative"
                        className="text-[10px]"
                      />
                    ) : b.exposure === "both" ? (
                      <MicroInsight
                        text="Mixed exposure — some paths are public."
                        tone="warning"
                        className="text-[10px]"
                      />
                    ) : undefined
                  }
                >
                  <div
                    className="h-full transition-[filter] hover:brightness-110 cursor-default"
                    style={{
                      width: `${(b.count / active.length) * 100}%`,
                      backgroundColor: EXPOSURE_COLOR[b.exposure],
                    }}
                  />
                </InsightTooltip>
              ))}
          </div>
          <div className="flex flex-wrap gap-3 text-[10px] text-muted-foreground">
            {buckets
              .filter((b) => b.count > 0)
              .map((b) => (
                <span key={b.exposure} className="flex items-center gap-1">
                  <span
                    className="h-2 w-2 rounded-sm"
                    style={{ backgroundColor: EXPOSURE_COLOR[b.exposure] }}
                  />
                  {EXPOSURE_LABEL[b.exposure]} {b.count}
                </span>
              ))}
          </div>
        </div>
      )}
    </ChartContainer>
  );
}
