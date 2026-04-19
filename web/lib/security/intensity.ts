/**
 * Controlled intensity model — calm by default, escalated on cause.
 *
 * The UI operates at 80% visual intensity by default and climbs toward 100%
 * only when the underlying data justifies urgency. Escalation is a tightening
 * of the existing system — higher contrast, heavier weight, signal halos,
 * focused hierarchy — NEVER a shift to a new palette or layout.
 *
 * Intensity climbs through four controlled axes and never through colour
 * saturation spikes or chrome decoration. See the refined playbook for the
 * full principle.
 */

import type { RiskSeverity } from "@/lib/types";

/** 0 = ambient, 4 = imminent. Used by every security primitive. */
export type IntensityLevel = 0 | 1 | 2 | 3 | 4;

/** Minimal shape the intensity calculator needs from a risk. */
export interface RiskSignals {
  severity: RiskSeverity;
  runtimeConfirmed: boolean;
  publicExposure: boolean;
}

/**
 * Derive the intensity level a risk should render at.
 *
 * Level 0 — Ambient:   info / low severity with no signals
 * Level 1 — Attentive: medium severity OR one signal active
 * Level 2 — Elevated:  high severity OR two signals active
 * Level 3 — Urgent:    critical + (runtime OR public)
 * Level 4 — Imminent:  critical + runtime + public (the loudest state)
 */
export function intensityFromSignals(signals: RiskSignals): IntensityLevel {
  const { severity, runtimeConfirmed, publicExposure } = signals;
  const signalCount = (runtimeConfirmed ? 1 : 0) + (publicExposure ? 1 : 0);

  if (severity === "critical" && runtimeConfirmed && publicExposure) return 4;
  if (severity === "critical" && (runtimeConfirmed || publicExposure)) return 3;
  if (severity === "critical" || severity === "high" || signalCount === 2) return 2;
  if (severity === "medium" || signalCount === 1) return 1;
  return 0;
}

/** Tailwind class name for the border that matches an intensity level. */
export function intensityBorderClass(level: IntensityLevel): string {
  // Level 3+ earns the stronger border. Below that, borders stay calm.
  return level >= 3 ? "border-border/80" : "border-border/60";
}

/** Box-shadow halo class for the supplied severity + intensity pair. */
export function intensityHaloStyle(
  level: IntensityLevel,
  severity: RiskSeverity,
): React.CSSProperties | undefined {
  // Halos are earned — only Level 3+ elements receive them.
  if (level < 3) return undefined;
  if (severity === "critical") return { boxShadow: "var(--halo-critical)" };
  // Non-critical risks at Level 3+ can still exist (e.g. runtime-confirmed
  // high severity). They receive a weaker halo via the exposure channel.
  return { boxShadow: "var(--halo-exposure)" };
}

/**
 * Font-weight token for numeric figures at a given intensity. Higher
 * intensity = heavier weight. Caps at font-bold so we never creep outside
 * the existing typographic scale.
 */
export function intensityNumberWeight(level: IntensityLevel): string {
  if (level >= 4) return "font-bold";
  if (level >= 2) return "font-semibold";
  return "font-medium";
}

/**
 * Translate an intensity level into a human time-language action title.
 *
 * Same five-level model as `intensityFromSignals`, just re-expressed as
 * the answer to "when do I need to act?". The verbs are intentionally
 * imperative ("Patch", "Schedule", "Monitor") because the NextBestAction
 * panel uses the title as its focal text and an imperative reads as a
 * decision the user can act on, not a description.
 *
 * Level 4 — Imminent:  "Patch immediately"
 * Level 3 — Urgent:    "Patch this week"
 * Level 2 — Elevated:  "Patch this sprint"
 * Level 1 — Attentive: "Schedule for next planning"
 * Level 0 — Ambient:   "Monitor only"
 */
export function intensityToActionTitle(level: IntensityLevel): string {
  switch (level) {
    case 4:
      return "Patch immediately";
    case 3:
      return "Patch this week";
    case 2:
      return "Patch this sprint";
    case 1:
      return "Schedule for next planning";
    case 0:
      return "Monitor only";
  }
}

/**
 * Severity → oklch CSS variable for the ring/bar fill. Returned as a bare
 * `var(--severity-x)` reference so consumers can drop it into `style={}`
 * or `className` alongside arbitrary Tailwind utilities.
 */
export function severityFillVar(severity: RiskSeverity): string {
  return `var(--severity-${severity})`;
}

/** Severity → a deterministic Tailwind text-colour class. */
export function severityTextClass(severity: RiskSeverity): string {
  switch (severity) {
    case "critical":
      return "text-severity-critical";
    case "high":
      return "text-severity-high";
    case "medium":
      return "text-severity-medium";
    case "low":
      return "text-severity-low";
    case "info":
      return "text-severity-info";
  }
}

/** Severity → a deterministic Tailwind background-colour class. */
export function severityBgClass(severity: RiskSeverity): string {
  switch (severity) {
    case "critical":
      return "bg-severity-critical";
    case "high":
      return "bg-severity-high";
    case "medium":
      return "bg-severity-medium";
    case "low":
      return "bg-severity-low";
    case "info":
      return "bg-severity-info";
  }
}
