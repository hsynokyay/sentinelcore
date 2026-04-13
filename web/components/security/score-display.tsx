"use client";

import { cn } from "@/lib/utils";
import type { RiskSeverity } from "@/lib/types";
import { severityFillVar, severityTextClass } from "@/lib/security/intensity";
import { ScoreRing } from "./score-ring";

export type ScoreDisplayVariant = "hero" | "lg" | "md" | "sm";
export type ScoreDisplayState = "active" | "resolved" | "muted";

export interface ScoreDisplayProps {
  /** The score to render. */
  score: number;
  /** Maximum score. Defaults to 100. */
  max?: number;
  /** Severity band. */
  severity: RiskSeverity;
  /** Which visual treatment to use. See the variantConfig below. */
  variant: ScoreDisplayVariant;
  /** Lifecycle state. `resolved` and `muted` desaturate the ring/bar graphics
   *  without dimming the number itself — the information stays crisp. */
  state?: ScoreDisplayState;
  /** Apply the severity glow on the ring (Level 3+ earned). */
  glow?: boolean;
  /** Play the one-time mount fill animation. Defaults to true. */
  animate?: boolean;
  /** Accessible label override. */
  "aria-label"?: string;
  className?: string;
}

/**
 * Per-variant layout constants. Kept small and literal so a future reader
 * can eyeball the full matrix. New variants should be added here and
 * nowhere else.
 */
const variantConfig = {
  hero: {
    ringSize: 160,
    ringStroke: 10,
    numberClass: "text-4xl font-bold leading-none",
    denominatorClass: "mt-1 text-[10px] uppercase tracking-widest text-muted-foreground",
    showDenominator: true,
    echoHeight: "h-1", // 4px
    showEcho: true,
  },
  lg: {
    ringSize: 96,
    ringStroke: 6,
    numberClass: "text-2xl font-bold leading-none",
    denominatorClass: "mt-0.5 text-[9px] uppercase tracking-widest text-muted-foreground",
    showDenominator: true,
    echoHeight: "h-0.5", // 2px
    showEcho: false,
  },
  md: {
    ringSize: 56,
    ringStroke: 4,
    numberClass: "text-base font-semibold leading-none",
    denominatorClass: "",
    showDenominator: false,
    echoHeight: "h-0.5",
    showEcho: false,
  },
  sm: {
    // `sm` is linear-only (no SVG ring). Used inside dense table rows.
    ringSize: 0,
    ringStroke: 0,
    numberClass: "text-sm font-semibold",
    denominatorClass: "",
    showDenominator: false,
    echoHeight: "h-1.5", // 6px — slightly chunkier for table rows
    showEcho: true,
  },
} as const;

/**
 * ScoreDisplay — the hero visualisation for a risk score.
 *
 * Hybrid radial + linear: every variant except `sm` renders a severity-
 * coloured progress ring with the score number centered inside. The
 * `hero` variant also renders a linear "echo" bar directly below the
 * ring, giving operators two redundant readings of the same value (ring
 * for glance, bar for precision comparison across rows).
 *
 * Variant picker:
 *   - hero:  risk detail header (160px ring + linear echo)
 *   - lg:    dashboard KPI popovers (96px ring)
 *   - md:    Top Risks card mini-score (56px ring)
 *   - sm:    dense table rows (no ring; linear bar + number only)
 */
export function ScoreDisplay({
  score,
  max = 100,
  severity,
  variant,
  state = "active",
  glow = false,
  animate = true,
  className,
  "aria-label": ariaLabel,
}: ScoreDisplayProps) {
  const clamped = Math.max(0, Math.min(max, score));
  const percent = clamped / max;
  const config = variantConfig[variant];
  const desaturated = state === "resolved" || state === "muted";

  // Graphics dim in a controlled way while the number stays full-strength.
  // Tailwind's `saturate-[.7]` drops saturation by 30% — the exact value
  // called for by the playbook. Opacity 40% keeps the shape perceptible.
  const graphicsDimClass = desaturated ? "opacity-40 saturate-[.7]" : "";

  const numberColorClass = severityTextClass(severity);

  const accessibleLabel = ariaLabel ?? `Risk score ${clamped} of ${max}`;

  if (variant === "sm") {
    // Linear-only variant — used inside table rows where density beats
    // drama. No ring, no SVG cost, minimal DOM.
    return (
      <div
        className={cn("inline-flex items-center gap-2", className)}
        role="progressbar"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-label={accessibleLabel}
      >
        <div
          className={cn(
            "w-14 overflow-hidden rounded-full bg-[var(--contrib-track)]",
            config.echoHeight,
            graphicsDimClass,
          )}
          aria-hidden="true"
        >
          <div
            className="h-full"
            style={{
              width: `${percent * 100}%`,
              backgroundColor: severityFillVar(severity),
              transition:
                "width var(--duration-score) var(--ease-out-sentinel)",
            }}
          />
        </div>
        <span
          className={cn(
            "tabular-nums",
            config.numberClass,
            numberColorClass,
          )}
        >
          {clamped}
        </span>
      </div>
    );
  }

  // Radial variants (hero / lg / md).
  return (
    <div
      className={cn("inline-flex flex-col items-center", className)}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-label={accessibleLabel}
    >
      {/* Ring + absolutely-positioned number. The ring lives inside a
          wrapper that can be dimmed independently; the number sits on
          top in its own sibling so desaturation never touches it. */}
      <div
        className="relative"
        style={{ width: config.ringSize, height: config.ringSize }}
      >
        <div className={cn("transition-[opacity,filter]", graphicsDimClass)}>
          <ScoreRing
            value={clamped}
            max={max}
            severity={severity}
            size={config.ringSize}
            strokeWidth={config.ringStroke}
            animate={animate}
            glow={glow && !desaturated}
          />
        </div>
        <div
          className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center"
          aria-hidden="true"
        >
          <span
            className={cn(
              "tabular-nums",
              config.numberClass,
              numberColorClass,
            )}
          >
            {clamped}
          </span>
          {config.showDenominator && (
            <span className={config.denominatorClass}>of {max}</span>
          )}
        </div>
      </div>

      {/* Linear echo below the ring (hero only). Matches the ring width
          so the two readings align vertically. */}
      {config.showEcho && (
        <div
          className={cn(
            "mt-2 overflow-hidden rounded-full bg-[var(--contrib-track)]",
            config.echoHeight,
            graphicsDimClass,
          )}
          style={{ width: config.ringSize }}
          aria-hidden="true"
        >
          <div
            className="h-full"
            style={{
              width: `${percent * 100}%`,
              backgroundColor: severityFillVar(severity),
              transition:
                "width var(--duration-score) var(--ease-out-sentinel)",
            }}
          />
        </div>
      )}
    </div>
  );
}
