"use client";

import { cn } from "@/lib/utils";
import type { RiskSeverity } from "@/lib/types";
import { useMountAnimation } from "@/lib/hooks/use-mount-animation";
import { severityFillVar } from "@/lib/security/intensity";

export interface ScoreRingProps {
  /** Current value (0..max). Clamped internally. */
  value: number;
  /** Maximum value. Defaults to 100. */
  max?: number;
  /** Severity band — determines the fill colour. */
  severity: RiskSeverity;
  /** Outer diameter in pixels. */
  size: number;
  /** Ring thickness in pixels. Defaults to ~10% of size, capped to [3, 12]. */
  strokeWidth?: number;
  /** Play the one-time mount fill animation. Defaults to true. */
  animate?: boolean;
  /** Apply the severity halo (Level 3+ only). Defaults to false. */
  glow?: boolean;
  /** Accessible label for the progressbar role. */
  "aria-label"?: string;
  className?: string;
}

/**
 * Thin SVG progress ring used inside ScoreDisplay. The ring:
 *   - starts at 12 o'clock and sweeps clockwise
 *   - fills with the severity colour from the design system
 *   - animates on mount via a CSS transition on stroke-dashoffset
 *   - respects prefers-reduced-motion (via useMountAnimation)
 *
 * The ring is deliberately stateless about content: the score number and
 * any "of max" caption are rendered by ScoreDisplay, absolutely positioned
 * on top of this SVG.
 */
export function ScoreRing({
  value,
  max = 100,
  severity,
  size,
  strokeWidth,
  animate = true,
  glow = false,
  className,
  "aria-label": ariaLabel,
}: ScoreRingProps) {
  const clamped = Math.max(0, Math.min(max, value));
  const percent = clamped / max;

  // Default stroke = 10% of diameter, clamped to a sensible range so the
  // hero variant (160px) and the md variant (56px) both look balanced.
  const stroke =
    strokeWidth ?? Math.max(3, Math.min(12, Math.round(size * 0.1)));
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const targetOffset = circumference * (1 - percent);

  // On mount we start with the ring empty (offset = circumference) and
  // transition to the target offset. useMountAnimation flips the gate to
  // `true` on the next client tick, which kicks the CSS transition. If
  // prefers-reduced-motion is set, it returns `true` synchronously so the
  // ring renders in its final state with no motion.
  const mounted = useMountAnimation();
  const renderedOffset = animate ? (mounted ? targetOffset : circumference) : targetOffset;

  const fill = severityFillVar(severity);
  const center = size / 2;

  // Glow is earned — only Level 3+ consumers pass `glow={true}`. We use a
  // drop-shadow filter rather than box-shadow because the host element is
  // an SVG, and box-shadow on SVGs is inconsistent across engines.
  const filterStyle = glow
    ? { filter: `drop-shadow(0 0 14px ${fill})` }
    : undefined;

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-label={ariaLabel ?? `Risk score ${clamped} of ${max}`}
      className={cn("block", className)}
      style={filterStyle}
    >
      {/* Track — the dim background ring. */}
      <circle
        cx={center}
        cy={center}
        r={radius}
        fill="none"
        stroke="var(--contrib-track)"
        strokeWidth={stroke}
      />

      {/* Fill arc — severity coloured, rotated so the arc starts at top. */}
      <circle
        cx={center}
        cy={center}
        r={radius}
        fill="none"
        stroke={fill}
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={renderedOffset}
        transform={`rotate(-90 ${center} ${center})`}
        style={{
          transition: animate
            ? "stroke-dashoffset var(--duration-score) var(--ease-out-sentinel)"
            : undefined,
        }}
      />
    </svg>
  );
}
