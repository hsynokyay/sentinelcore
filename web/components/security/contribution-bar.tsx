"use client";

import { cn } from "@/lib/utils";
import { useMountAnimation } from "@/lib/hooks/use-mount-animation";

/**
 * The visual category of a single contribution to a risk score.
 *
 * - `base`    — the seed score that severity contributes (always positive,
 *               drawn in neutral grey so it reads as the floor).
 * - `boost`   — a positive signal that pushed the score up (runtime confirm,
 *               public exposure, repeated finding, etc).
 * - `penalty` — a signal that pulled the score down (sanitizer present,
 *               low confidence, mitigations detected).
 *
 * Each kind maps to its own oklch token in `app/globals.css`, so consumers
 * never need to know the colour values.
 */
export type ContributionKind = "base" | "boost" | "penalty";

export interface ContributionBarProps {
  /** Display label for the contribution (the human-readable rationale). */
  label: string;
  /** Signed weight. Boosts are positive, penalties negative, base positive. */
  weight: number;
  /** Maximum |weight| across all contributions in the panel. Used to
   *  normalize the bar width — the largest contribution renders at 100%
   *  and everything else scales relative to it. */
  maxAbsWeight: number;
  /** Visual category. Drives the bar colour and the weight number colour. */
  kind: ContributionKind;
  /** When true, the bar plays a one-time mount fill animation from 0% to
   *  its target width. Defaults to true. */
  animate?: boolean;
  className?: string;
}

const kindToColorVar: Record<ContributionKind, string> = {
  base: "var(--contrib-base)",
  boost: "var(--contrib-boost)",
  penalty: "var(--contrib-penalty)",
};

/**
 * ContributionBar — visualises one piece of score evidence as a normalized
 * horizontal bar with the label above and the signed weight on the right.
 *
 * The width is `|weight| / maxAbsWeight`, so a panel of contributions
 * communicates relative magnitude at a glance: the longest bar is the
 * dominant signal, no number-reading required. Bar colour and weight-number
 * colour come from the same token, so the eye groups them as one unit.
 *
 * On mount, the bar fills from 0% to its target width over `--duration-score`
 * with the SentinelCore ease curve, matching the ScoreDisplay echo bar.
 * The `useMountAnimation` hook returns true after a double rAF so the
 * browser actually paints the empty starting frame before the transition
 * fires (the same React 19 batching workaround used by ScoreRing).
 */
export function ContributionBar({
  label,
  weight,
  maxAbsWeight,
  kind,
  animate = true,
  className,
}: ContributionBarProps) {
  const mounted = useMountAnimation(0);

  // Normalize. Guard against a degenerate panel where maxAbsWeight is 0:
  // we still render the row (label + weight), just with an empty bar.
  const targetPct =
    maxAbsWeight > 0
      ? Math.min(100, (Math.abs(weight) / maxAbsWeight) * 100)
      : 0;
  const renderedPct = animate && !mounted ? 0 : targetPct;

  const colorVar = kindToColorVar[kind];
  // Positive weights need an explicit "+" prefix; negative weights already
  // carry the minus from the value itself.
  const formattedWeight = weight > 0 ? `+${weight}` : `${weight}`;

  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex items-baseline justify-between gap-3 text-sm">
        {/* Labels can be long ("Exposed on public surface https://...") so
            we let them wrap rather than truncating — the user needs the
            full rationale. The bar provides the visual anchor for
            proportionality even when the label spans two lines. */}
        <span className="text-foreground leading-snug">{label}</span>
        <span
          className="font-mono tabular-nums shrink-0"
          style={{ color: colorVar }}
        >
          {formattedWeight}
        </span>
      </div>
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--contrib-track)]"
        aria-hidden="true"
      >
        <div
          className="h-full"
          style={{
            width: `${renderedPct}%`,
            backgroundColor: colorVar,
            transition:
              "width var(--duration-score) var(--ease-out-sentinel)",
          }}
        />
      </div>
    </div>
  );
}
