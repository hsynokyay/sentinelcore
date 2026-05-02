"use client";

import { ChartContainer } from "@/components/security/chart-container";
import { MicroInsight } from "@/components/security/micro-insight";
import { InsightTooltip } from "@/components/security/insight-tooltip";
import { isRuntimeConfirmed } from "@/lib/security/runtime";
import type { RiskCluster } from "@/lib/types";

/**
 * RuntimeConfirmedCard — shows the proportion of active risks that
 * have been confirmed at runtime (DAST corroborated the SAST finding).
 * This is the single strongest trust signal in the risk model — a
 * runtime-confirmed risk is almost certainly exploitable.
 */
export function RuntimeConfirmedCard({
  risks,
  isLoading = false,
}: {
  risks: RiskCluster[];
  isLoading?: boolean;
}) {
  const active = risks.filter((r) => r.status === "active");
  const confirmed = active.filter(isRuntimeConfirmed);
  const unconfirmed = active.length - confirmed.length;
  const pct =
    active.length > 0 ? Math.round((confirmed.length / active.length) * 100) : 0;

  const insightText =
    confirmed.length === 0
      ? "No risks confirmed at runtime."
      : `${confirmed.length} of ${active.length} active risks (${pct}%) confirmed at runtime.`;
  const insightTone =
    confirmed.length === 0
      ? "positive"
      : pct >= 50
        ? "negative"
        : "warning";

  return (
    <ChartContainer
      title="Runtime confirmation"
      insight={
        !isLoading ? (
          <MicroInsight
            text={insightText}
            tone={insightTone}
          />
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
            aria-label={`${confirmed.length} confirmed, ${unconfirmed} unconfirmed`}
          >
            {confirmed.length > 0 && (
              <InsightTooltip
                content={
                  <p className="font-semibold">
                    {confirmed.length} runtime-confirmed
                  </p>
                }
                footer={
                  <MicroInsight
                    text="These risks are exploitable — prioritise them."
                    tone="negative"
                    className="text-[10px]"
                  />
                }
              >
                <div
                  className="h-full bg-[var(--signal-runtime)] transition-[filter] hover:brightness-110 cursor-default"
                  style={{
                    width: `${(confirmed.length / active.length) * 100}%`,
                  }}
                />
              </InsightTooltip>
            )}
            {unconfirmed > 0 && (
              <InsightTooltip
                content={
                  <p className="font-semibold">
                    {unconfirmed} not yet confirmed
                  </p>
                }
                footer={
                  <MicroInsight
                    text="May still be exploitable — SAST-only evidence."
                    tone="neutral"
                    className="text-[10px]"
                  />
                }
              >
                <div
                  className="h-full bg-muted transition-[filter] hover:brightness-110 cursor-default"
                  style={{
                    width: `${(unconfirmed / active.length) * 100}%`,
                  }}
                />
              </InsightTooltip>
            )}
          </div>
          <div className="flex gap-4 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-sm bg-[var(--signal-runtime)]" />
              Confirmed {confirmed.length}
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-sm bg-muted" />
              Unconfirmed {unconfirmed}
            </span>
          </div>
        </div>
      )}
    </ChartContainer>
  );
}
