"use client";

import { cn } from "@/lib/utils";
import type { RiskSeverity } from "@/lib/types";
import { severityBgClass } from "@/lib/security/intensity";

export type SeverityStripState = "active" | "resolved" | "muted";
export type SeverityStripOrientation = "vertical" | "horizontal";

export interface SeverityStripProps {
  severity: RiskSeverity;
  /** Lifecycle state. resolved / muted desaturate the strip. */
  state?: SeverityStripState;
  /** Vertical = left rail (default). Horizontal = top rail for cards. */
  orientation?: SeverityStripOrientation;
  /** Override the default 3px thickness. */
  thickness?: number;
  /** Optional aria-label. Defaults to aria-hidden because the strip is a
   *  decorative companion to the textual SeverityBadge. Pass an explicit
   *  label only when the strip is the sole signal in its context. */
  "aria-label"?: string;
  className?: string;
}

/**
 * SeverityStrip — the thin coloured rail that anchors a row, card, or
 * list item to its severity band at a glance.
 *
 * The strip is a peripheral signal, not a focal element: it sits on the
 * edge, draws zero attention by default, and lets a sibling SeverityBadge
 * carry the textual meaning. resolved / muted states desaturate it in the
 * same controlled-intensity way the ScoreDisplay desaturates its ring.
 *
 * Sizing strategy: absolute positioning. The strip uses
 * `position: absolute` with `inset-y-0` (or `inset-x-0` for horizontal)
 * to fill its parent's cross-axis. The parent MUST be a positioned
 * containing block — set `position: relative` on the wrapping element.
 *
 * This single strategy works in every context the strip needs:
 *
 *  - Inside a `<td>` table cell, set `relative` on the cell.
 *  - Inside a flex / grid card, set `relative` on the wrapping section.
 *  - Inside a static `<div>`, set `relative` on the div.
 *
 * Older approaches (h-px shrink trick, align-self: stretch) only worked
 * in one container at a time. Absolute positioning is the universal
 * fix — supported by every browser since position: relative on `<td>`
 * shipped in modern engines (~2018).
 *
 * The consumer is responsible for reserving space next to the strip
 * (e.g. `padding-left: 5` on the content) — absolute positioning takes
 * the strip out of normal flow, so the next sibling won't be auto-pushed.
 */
export function SeverityStrip({
  severity,
  state = "active",
  orientation = "vertical",
  thickness = 3,
  "aria-label": ariaLabel,
  className,
}: SeverityStripProps) {
  const desaturated = state === "resolved" || state === "muted";
  const isVertical = orientation === "vertical";

  // Vertical: pin top + bottom + left, set explicit width.
  // Horizontal: pin left + right + top, set explicit height.
  const positionStyle: React.CSSProperties = isVertical
    ? {
        position: "absolute",
        top: 0,
        bottom: 0,
        left: 0,
        width: thickness,
      }
    : {
        position: "absolute",
        left: 0,
        right: 0,
        top: 0,
        height: thickness,
      };

  return (
    <span
      role={ariaLabel ? "img" : undefined}
      aria-hidden={ariaLabel ? undefined : true}
      aria-label={ariaLabel}
      className={cn(
        "block",
        isVertical ? "rounded-r-sm" : "rounded-b-sm",
        severityBgClass(severity),
        desaturated && "opacity-40 saturate-[.7]",
        // The graphics-dim transition mirrors the ScoreDisplay's so that
        // a row entering the resolved state animates uniformly across both
        // its rail and its score ring/echo.
        "transition-[opacity,filter] duration-[var(--duration-base)]",
        className,
      )}
      style={positionStyle}
    />
  );
}
