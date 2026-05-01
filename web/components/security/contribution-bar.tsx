"use client";

import { Layers, TrendingUp, TrendingDown } from "lucide-react";
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
  /** Visual category. Drives the bar colour, glyph, and weight number colour. */
  kind: ContributionKind;
  /** Mount animation delay in ms. Used by the parent panel to stagger the
   *  cascade: row 0 = 0ms, row 1 = 80ms, row 2 = 160ms, etc. The bar
   *  fills from 0% to its target width after this delay. Defaults to 0. */
  staggerDelay?: number;
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
 * Category glyphs — a small icon before the label that gives each
 * contribution type a distinct visual anchor. The icons are chosen for
 * their directional semantics: Layers (stacked floor), TrendingUp
 * (positive boost), TrendingDown (negative penalty).
 */
const kindToIcon: Record<
  ContributionKind,
  React.ComponentType<{ className?: string }>
> = {
  base: Layers,
  boost: TrendingUp,
  penalty: TrendingDown,
};

/**
 * ContributionBar — visualises one piece of score evidence as a normalized
 * horizontal bar with a category glyph + label + signed weight, and a
 * proportional fill bar below.
 *
 * Layout per row:
 *   [glyph] Label text                                    +30
 *   ████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
 *
 * The width is `|weight| / maxAbsWeight`, so a panel of contributions
 * communicates relative magnitude at a glance: the longest bar is the
 * dominant signal, no number-reading required. Bar colour, glyph colour,
 * and weight-number colour come from the same token, so the eye groups
 * them as one unit.
 *
 * Staggered animation: each bar accepts a `staggerDelay` that offsets
 * its fill start from the panel mount. The parent passes incremented
 * delays (0, 80, 160…) so bars cascade in from top to bottom — the
 * dominant signal fills first, lesser signals follow. The effect is
 * subtle (80ms between rows) but it communicates hierarchy: your eye
 * tracks the cascade and lands on the largest bar before the smaller
 * ones have finished.
 */
export function ContributionBar({
  label,
  weight,
  maxAbsWeight,
  kind,
  staggerDelay = 0,
  animate = true,
  className,
}: ContributionBarProps) {
  const mounted = useMountAnimation(staggerDelay);

  // Normalize. Guard against a degenerate panel where maxAbsWeight is 0:
  // we still render the row (label + weight), just with an empty bar.
  const targetPct =
    maxAbsWeight > 0
      ? Math.min(100, (Math.abs(weight) / maxAbsWeight) * 100)
      : 0;
  const renderedPct = animate && !mounted ? 0 : targetPct;

  const colorVar = kindToColorVar[kind];
  const formattedWeight = weight > 0 ? `+${weight}` : `${weight}`;
  const Icon = kindToIcon[kind];
  const kindIconClass: Record<ContributionKind, string> = {
    base: "text-[var(--contrib-base)]",
    boost: "text-[var(--contrib-boost)]",
    penalty: "text-[var(--contrib-penalty)]",
  };

  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span className="inline-flex items-baseline gap-1.5 text-foreground leading-snug min-w-0">
          <Icon
            aria-hidden="true"
            className={cn("size-3.5 shrink-0 self-center", kindIconClass[kind])}
          />
          {/* Labels can be long ("Exposed on public surface https://...")
              so we let them wrap rather than truncating. The bar below
              provides the visual anchor for proportionality even when the
              label spans two lines. */}
          <span>{label}</span>
        </span>
        <span
          className="font-mono tabular-nums shrink-0"
          style={{ color: colorVar }}
        >
          {formattedWeight}
        </span>
      </div>
      <div
        className="h-1 w-full overflow-hidden rounded-full bg-[var(--contrib-track)]"
        aria-hidden="true"
      >
        <div
          className="h-full rounded-full"
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
