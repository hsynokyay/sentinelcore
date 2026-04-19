"use client";

import { cn } from "@/lib/utils";
import type { RiskSeverity } from "@/lib/types";
import { severityTextClass } from "@/lib/security/intensity";

export type IntegratedLabelPlacement =
  | "top-left"
  | "top-right"
  | "bottom-left"
  | "bottom-right"
  | "center";

export interface IntegratedLabelProps {
  /** The label text. Keep it very short (1-3 words) — this is an inline
   *  annotation, not a paragraph. */
  text: string;
  /** Where to place the label relative to its positioned parent.
   *  The parent MUST be `position: relative`. */
  placement?: IntegratedLabelPlacement;
  /** Optional severity tint so the label colour matches the chart
   *  element it annotates. When omitted, uses muted-foreground. */
  severity?: RiskSeverity;
  /** Visual weight. `subtle` (default) is smaller + more transparent;
   *  `bold` is a touch larger + full opacity for key callouts. */
  weight?: "subtle" | "bold";
  className?: string;
}

const placementClass: Record<IntegratedLabelPlacement, string> = {
  "top-left": "top-1 left-1",
  "top-right": "top-1 right-1",
  "bottom-left": "bottom-1 left-1",
  "bottom-right": "bottom-1 right-1",
  center: "top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2",
};

/**
 * IntegratedLabel — a small absolutely-positioned text annotation that
 * sits directly on or next to a chart element. Used for:
 *
 *  - Segment labels on a stacked bar ("Critical", "High")
 *  - Reference-line values on a scatter plot ("avg 45")
 *  - Threshold markers on a gauge ("SLA breach")
 *
 * The label is *part of the chart*, not chrome around it. It uses the
 * same severity text classes as the rest of the security surface so a
 * "Critical" label on a red chart segment is the same red as the
 * SeverityBadge in the table row — one visual vocabulary.
 *
 * The parent element must be `position: relative` (or absolute/fixed)
 * for the placement to work. The label is `pointer-events-none` so it
 * doesn't interfere with hover targets underneath.
 */
export function IntegratedLabel({
  text,
  placement = "top-left",
  severity,
  weight = "subtle",
  className,
}: IntegratedLabelProps) {
  const colorClass = severity
    ? severityTextClass(severity)
    : "text-muted-foreground";
  const sizeClass =
    weight === "bold"
      ? "text-[11px] font-semibold"
      : "text-[10px] font-medium opacity-70";

  return (
    <span
      aria-hidden="true"
      className={cn(
        "absolute pointer-events-none select-none whitespace-nowrap leading-none",
        placementClass[placement],
        colorClass,
        sizeClass,
        className,
      )}
    >
      {text}
    </span>
  );
}
