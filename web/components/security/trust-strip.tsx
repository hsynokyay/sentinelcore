"use client";

import { cn } from "@/lib/utils";
import { TrustChip, type TrustChipProps, type TrustState } from "./trust-chip";
import { PulseDot, type PulseDotTone } from "./pulse-dot";

/**
 * One signal in a TrustStrip — same shape as TrustChipProps minus
 * `className` (the strip handles spacing). Each signal is a single
 * facet of the entity's overall trust state — verification, scope,
 * rate limit, recency, etc.
 */
export type TrustSignal = Omit<TrustChipProps, "className">;

export interface TrustStripProps {
  /** Ordered list of trust signals. The first signal is the most
   *  prominent — usually the canonical "is this thing verified?" answer. */
  signals: TrustSignal[];
  /** Optional leading PulseDot for the *overall* trust posture across
   *  all signals. Use when the strip needs a single at-a-glance read
   *  before the chips. The dot pulses by default. */
  overallPulse?: PulseDotTone;
  /** Stable id passed to the leading dot, for accessibility. */
  "aria-label"?: string;
  className?: string;
}

/**
 * TrustStrip — a horizontal ribbon of TrustChips that summarises the
 * complete trust state of an entity. Designed for places where one
 * chip isn't enough: a scan target's row needs verification status AND
 * scope-restriction state AND rate-limit state to fully describe its
 * trust posture. A single chip would over-simplify; three separate
 * columns would over-fragment. The strip is the right granularity.
 *
 * Layout: a flex row with `gap-1.5` between chips so the strip stays
 * dense in table cells but legible in card detail views. The optional
 * `overallPulse` PulseDot sits at the start of the row when the
 * consumer wants a single-glance summary.
 *
 * The strip is intentionally a thin composer — no new visual chrome,
 * just spacing and an optional pulse dot. The TrustChip primitive
 * carries all the colour and icon work, so a future palette change
 * propagates to every strip without touching this file.
 */
export function TrustStrip({
  signals,
  overallPulse,
  "aria-label": ariaLabel,
  className,
}: TrustStripProps) {
  return (
    <div
      role={ariaLabel ? "group" : undefined}
      aria-label={ariaLabel}
      className={cn(
        "inline-flex flex-wrap items-center gap-1.5",
        className,
      )}
    >
      {overallPulse && (
        <PulseDot
          tone={overallPulse}
          size="xs"
          aria-label={ariaLabel ? `${ariaLabel} status` : undefined}
        />
      )}
      {signals.map((signal, idx) => (
        <TrustChip key={`${idx}-${signal.state}-${signal.label ?? ""}`} {...signal} />
      ))}
    </div>
  );
}

/**
 * Re-export TrustState so consumers can build typed signal arrays
 * without reaching into trust-chip.
 */
export type { TrustState };
