"use client";

/**
 * Debug-only matrix for the ScoreDisplay primitive.
 *
 * Renders every (variant × severity × state) combination on one page so a
 * designer can eyeball the full surface area without a Storybook. Lives
 * under the dashboard group to reuse the shell + auth; not linked from
 * the sidebar. Delete this file (or add a feature flag) before release.
 */

import { useState } from "react";
import { ScoreDisplay } from "@/components/security/score-display";
import type { RiskSeverity } from "@/lib/types";

type State = "active" | "resolved" | "muted";

const severities: RiskSeverity[] = ["critical", "high", "medium", "low", "info"];

// Representative scores per severity so each ring has a different angle
// — useful for catching off-by-one / rounding errors in the SVG math.
const scoreBySeverity: Record<RiskSeverity, number> = {
  critical: 85,
  high: 65,
  medium: 45,
  low: 25,
  info: 10,
};

const variants = ["hero", "lg", "md", "sm"] as const;
const states: State[] = ["active", "resolved", "muted"];

export default function ScoreDisplayDebugPage() {
  // Bumping this key remounts every ScoreDisplay in place, replaying the
  // mount-fill animation without a page navigation. Used for visual QA.
  const [replayKey, setReplayKey] = useState(0);

  return (
    <div className="space-y-12 p-8">
      <header className="flex items-start justify-between gap-6">
        <div>
          <h1 className="text-2xl font-semibold">ScoreDisplay matrix</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Debug-only page. Renders every variant × severity × state to
            catch visual regressions before component consumers ship. Not
            linked from the sidebar; navigate via the URL.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setReplayKey((k) => k + 1)}
          className="shrink-0 rounded-md border border-border bg-card px-3 py-1.5 text-sm font-medium hover:bg-accent"
        >
          Replay animation
        </button>
      </header>

      {variants.map((variant) => (
        <section key={variant} className="space-y-6">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
            Variant · {variant}
          </h2>

          {states.map((state) => (
            <div key={state} className="rounded-lg border border-border bg-card p-6">
              <div className="mb-4 text-xs uppercase tracking-wider text-muted-foreground">
                State · {state}
              </div>
              <div className="flex flex-wrap items-end gap-10">
                {severities.map((severity) => (
                  <div
                    key={severity}
                    className="flex flex-col items-center gap-3"
                  >
                    <ScoreDisplay
                      // The replayKey forces an unmount/remount when the
                      // user clicks the Replay button, so the mount fill
                      // animation plays again without reloading the page.
                      key={`${variant}-${state}-${severity}-${replayKey}`}
                      score={scoreBySeverity[severity]}
                      severity={severity}
                      variant={variant}
                      state={state}
                      // Glow is earned: only critical-severity, active-state
                      // rings receive the halo. Demonstrates the
                      // "controlled intensity" rule.
                      glow={severity === "critical" && state === "active"}
                    />
                    <span className="text-[10px] uppercase tracking-widest text-muted-foreground">
                      {severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </section>
      ))}
    </div>
  );
}
