"use client";

import { cn } from "@/lib/utils";

/**
 * Three-tone pulse semantics:
 *
 * - `ok`   — system operational, signal nominal. Maps to `--pulse-ok` (green).
 * - `warn` — degraded but not down. Maps to `--pulse-warn` (yellow).
 * - `err`  — failure or active alarm. Maps to `--pulse-err` (red).
 */
export type PulseDotTone = "ok" | "warn" | "err";

export type PulseDotSize = "xs" | "sm" | "md";

export interface PulseDotProps {
  /** Tone — drives the dot colour from existing design tokens. */
  tone: PulseDotTone;
  /** Size preset. xs = 6px, sm = 8px (default), md = 10px. */
  size?: PulseDotSize;
  /** Whether the dot pulses. Defaults to `true`. Pass `false` for a
   *  static dot — useful when the consumer is communicating "currently
   *  this state" rather than "actively signalling". */
  pulsing?: boolean;
  /** Optional accessible label. When provided, the dot becomes a
   *  `role="status"` element with the label, so screen readers
   *  announce it. When omitted, the dot is decorative and `aria-hidden`. */
  "aria-label"?: string;
  className?: string;
}

const sizeClass: Record<PulseDotSize, string> = {
  xs: "h-1.5 w-1.5", // 6px
  sm: "h-2 w-2", // 8px
  md: "h-2.5 w-2.5", // 10px
};

const toneClass: Record<PulseDotTone, string> = {
  ok: "bg-[var(--pulse-ok)]",
  warn: "bg-[var(--pulse-warn)]",
  err: "bg-[var(--pulse-err)]",
};

/**
 * PulseDot — a tiny circular indicator that pulses to communicate live
 * status. Used in the page header for ESTOP / system-online state, in
 * scan rows to mark "currently running", inside TrustChips for "active
 * alarm", and anywhere else a one-character live signal is needed.
 *
 * Animation comes from the `pulse-trust` keyframe in `globals.css`,
 * which animates opacity 1 → 0.35 → 1 over 2 seconds. The keyframe is
 * already wired into `prefers-reduced-motion: reduce` (collapses to
 * 0.01ms), so users with reduced-motion preferences see a static dot
 * with no extra work from the consumer.
 *
 * Animation is applied via inline `style` rather than a Tailwind
 * arbitrary-value class to keep the keyframe reference explicit and
 * to bypass any v4 utility-tree-shaking surprises.
 */
export function PulseDot({
  tone,
  size = "sm",
  pulsing = true,
  "aria-label": ariaLabel,
  className,
}: PulseDotProps) {
  return (
    <span
      role={ariaLabel ? "status" : undefined}
      aria-label={ariaLabel}
      aria-hidden={ariaLabel ? undefined : true}
      className={cn(
        "inline-block shrink-0 rounded-full",
        sizeClass[size],
        toneClass[tone],
        className,
      )}
      style={
        pulsing
          ? { animation: "pulse-trust 2s ease-in-out infinite" }
          : undefined
      }
    />
  );
}
