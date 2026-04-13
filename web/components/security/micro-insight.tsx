"use client";

import { cn } from "@/lib/utils";

/**
 * Tone is the value-judgement axis. The text colour is derived from this
 * so the operator's eye groups insights by sentiment without having to
 * read every line.
 *
 * - `positive` — good news ("Critical down 2 this week")
 * - `negative` — bad news ("Critical up 2 this week")
 * - `warning` — caution-but-not-bad ("3 risks haven't been triaged")
 * - `neutral` — informational fact ("Most active risks are SQL injection")
 */
export type MicroInsightTone = "positive" | "negative" | "warning" | "neutral";

export interface MicroInsightProps {
  /** The insight text. Keep it under ~100 chars — anything longer should
   *  go in a panel, not an inline insight. */
  text: string;
  /** Tone for colour. Defaults to neutral so insights don't shout
   *  unless the consumer explicitly opts into a value judgement. */
  tone?: MicroInsightTone;
  /** Optional inline icon (e.g., a Lucide arrow or warning glyph)
   *  rendered to the left of the text. */
  icon?: React.ReactNode;
  className?: string;
}

/**
 * MicroInsight — a one-line tone-aware text primitive that turns a
 * computed observation into a glance-readable sentence.
 *
 * The point of MicroInsight is "look first, count second": instead of
 * making the operator scan a chart and reach a conclusion, the chart
 * states the conclusion above itself. The chart is then the *evidence*
 * for the insight, not the message.
 *
 * Designed to slot into:
 *  - The header of a ChartContainer ("All 7 critical risks are SQL injection")
 *  - The top of a list page (above ChangeSummaryStrip when a single
 *    sentence captures more than four numbers can)
 *  - Inside an InsightTooltip as the focal text
 *
 * Tone colours come from the existing design tokens — no new palette.
 * Negative pulls from --severity-critical, positive from --contrib-boost,
 * warning from --severity-high, neutral from --foreground.
 */
const toneClass: Record<MicroInsightTone, string> = {
  positive: "text-[var(--contrib-boost)]",
  negative: "text-severity-critical",
  warning: "text-severity-high",
  neutral: "text-foreground",
};

export function MicroInsight({
  text,
  tone = "neutral",
  icon,
  className,
}: MicroInsightProps) {
  return (
    <p
      className={cn(
        "inline-flex items-center gap-1.5 text-sm leading-snug",
        toneClass[tone],
        className,
      )}
    >
      {icon && (
        <span aria-hidden="true" className="shrink-0 inline-flex">
          {icon}
        </span>
      )}
      <span>{text}</span>
    </p>
  );
}
