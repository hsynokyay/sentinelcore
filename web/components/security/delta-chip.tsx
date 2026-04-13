"use client";

import { cn } from "@/lib/utils";

/**
 * Polarity tells the chip how to interpret the sign of the value.
 *
 * - `bad-when-positive` — positive deltas are bad news (e.g. risk counts,
 *   open findings, SLA breaches). Positive renders red, negative green.
 * - `good-when-positive` — positive deltas are good news (e.g. resolved
 *   counts, fixed findings, SLA-compliant work). Positive renders green,
 *   negative red.
 * - `neutral` — sign is informational only, no value judgement. Both
 *   directions render in the muted-foreground colour. Use for things like
 *   throughput counts where "more" and "less" are both just facts.
 */
export type DeltaPolarity =
  | "bad-when-positive"
  | "good-when-positive"
  | "neutral";

export interface DeltaChipProps {
  /** Signed delta value. */
  value: number;
  /** Optional caption rendered after the value (e.g. "this week",
   *  "vs last scan"). Kept short — the chip is meant to fit on one line. */
  label?: string;
  /** How to interpret the sign. Defaults to `bad-when-positive` because
   *  the most common SentinelCore consumer is a risk-count delta and
   *  defaulting saves callers from spelling it out every time. */
  polarity?: DeltaPolarity;
  /** Visual treatment. `subtle` (default) is a faint tinted background;
   *  `outline` is a bordered chip; `bare` is text only with no chrome. */
  variant?: "subtle" | "outline" | "bare";
  className?: string;
}

/**
 * Resolve the polarity + sign into one of three semantic states. Zero is
 * always neutral regardless of polarity — there's nothing to celebrate
 * or worry about a delta of zero.
 */
function resolveTone(
  value: number,
  polarity: DeltaPolarity,
): "bad" | "good" | "neutral" {
  if (value === 0 || polarity === "neutral") return "neutral";
  if (polarity === "bad-when-positive") return value > 0 ? "bad" : "good";
  return value > 0 ? "good" : "bad";
}

/**
 * Tone → background-and-text class pairs for each variant. Kept literal
 * so a future reader can eyeball the full matrix without chasing helpers.
 *
 * Backgrounds use the existing severity / contrib oklch tokens at low
 * alpha so the chips harmonise with the rest of the security surface
 * (no new colour palette).
 */
const toneClasses: Record<
  "subtle" | "outline" | "bare",
  Record<"bad" | "good" | "neutral", string>
> = {
  subtle: {
    bad: "bg-[color-mix(in_oklch,var(--severity-critical)_15%,transparent)] text-severity-critical",
    good: "bg-[color-mix(in_oklch,var(--contrib-boost)_15%,transparent)] text-[var(--contrib-boost)]",
    neutral: "bg-muted text-muted-foreground",
  },
  outline: {
    bad: "border border-[color-mix(in_oklch,var(--severity-critical)_40%,transparent)] text-severity-critical",
    good: "border border-[color-mix(in_oklch,var(--contrib-boost)_40%,transparent)] text-[var(--contrib-boost)]",
    neutral: "border border-border text-muted-foreground",
  },
  bare: {
    bad: "text-severity-critical",
    good: "text-[var(--contrib-boost)]",
    neutral: "text-muted-foreground",
  },
};

/**
 * DeltaChip — a small inline chip that displays a signed delta with
 * polarity-aware colour. Used in change-summary tiles, KPI cards, and
 * any place a number needs a "compared to what?" companion.
 *
 * The chip is intentionally tiny (xs text, tight padding) — its job is
 * to *qualify* a primary number, not compete with it. If a delta starts
 * to feel like the focal element, you're probably using the wrong
 * primitive — reach for `<NextBestAction>` or a full panel instead.
 *
 * Number formatting:
 *  - Positive: `+5`
 *  - Negative: `-3` (sign comes from the value itself)
 *  - Zero:     `0`
 *
 * The `label` is rendered after the number with a small left margin so
 * the value stays the focal point — "+5 this week", not "this week +5".
 */
export function DeltaChip({
  value,
  label,
  polarity = "bad-when-positive",
  variant = "subtle",
  className,
}: DeltaChipProps) {
  const tone = resolveTone(value, polarity);
  const formattedValue = value > 0 ? `+${value}` : `${value}`;
  const toneClass = toneClasses[variant][tone];

  // Padding and rounding scale with variant: bare has no chrome at all,
  // subtle is the default chip, outline mirrors subtle but with a border
  // instead of a fill.
  const chromeClass =
    variant === "bare" ? "" : "rounded-md px-1.5 py-0.5";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 text-xs font-mono tabular-nums whitespace-nowrap",
        chromeClass,
        toneClass,
        className,
      )}
      aria-label={label ? `${formattedValue} ${label}` : formattedValue}
    >
      <span>{formattedValue}</span>
      {label && (
        <span className="font-sans text-[10px] opacity-75">{label}</span>
      )}
    </span>
  );
}
