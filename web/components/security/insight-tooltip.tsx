"use client";

import { Tooltip } from "@base-ui/react/tooltip";
import { cn } from "@/lib/utils";

export interface InsightTooltipProps {
  /** The trigger element. The tooltip opens on hover/focus over this. */
  children: React.ReactNode;
  /** The tooltip body. Can be plain text, a MicroInsight, a small table,
   *  or any rich content — the popup is unopinionated about layout. */
  content: React.ReactNode;
  /** Side preference. Defaults to top, with auto-flip to avoid viewport
   *  collisions (handled by base-ui's positioner). */
  side?: "top" | "right" | "bottom" | "left";
  /** Whether the tooltip body itself can be hovered without closing the
   *  tooltip. Useful for tooltips that contain links. Defaults to false. */
  hoverable?: boolean;
  /** Optional className for the popup, in case a consumer needs to
   *  override max-width or padding for a specific instance. */
  popupClassName?: string;
}

/**
 * InsightTooltip — a styled wrapper around base-ui's Tooltip primitive
 * that gives every consumer the same calm-by-default popup chrome.
 *
 * The popup uses the existing card / border / muted-foreground tokens,
 * tabular-nums for any numbers inside, and a soft drop shadow that
 * matches the rest of the security surface. Animation is a 150ms fade
 * + 4px Y-shift on the data-state="open" transition — fast enough to
 * feel snappy, slow enough to read as motion rather than a flash.
 *
 * Designed to wrap any element: a SeverityBadge, a chart segment, a
 * ChangeSummaryStrip tile, or a single number in a paragraph. The
 * popup body is rich content, not just a string, so it can host a
 * MicroInsight, a mini-table, or a list of contributing items.
 *
 * Example usage in a chart:
 *
 *   <InsightTooltip
 *     content={
 *       <>
 *         <p className="font-semibold">Critical · 7 risks</p>
 *         <p className="text-muted-foreground">26% of active surface</p>
 *       </>
 *     }
 *   >
 *     <rect ... />
 *   </InsightTooltip>
 */
export function InsightTooltip({
  children,
  content,
  side = "top",
  hoverable = false,
  popupClassName,
}: InsightTooltipProps) {
  // Open/close delays live on `Tooltip.Provider` (a parent component
  // that groups multiple tooltips and shares timings). For now we lean
  // on base-ui's defaults — fast enough to feel responsive, slow enough
  // to avoid hover-thrash. If a future page has a dense cluster of
  // tooltips that should "pop instantly after the first one", drop a
  // <Tooltip.Provider delay={...}> in the dashboard layout.
  return (
    <Tooltip.Root disableHoverablePopup={!hoverable}>
      <Tooltip.Trigger
        // `render={null}` would let the trigger inherit a child element,
        // but base-ui's default — wrap the children in a span — is fine
        // for our use cases (badge / chart segment / number). The span
        // is `display: contents` so it doesn't affect layout.
        render={<span style={{ display: "contents" }} />}
      >
        {children}
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Positioner side={side} sideOffset={6}>
          <Tooltip.Popup
            className={cn(
              // Layout
              "z-50 max-w-xs rounded-md border bg-card px-3 py-2 text-xs text-foreground",
              // Soft elevation that matches the security surface — not
              // a heavy app-shell shadow, just enough to lift it off the
              // background.
              "shadow-md",
              // Animation: fade + 4px shift, gated by base-ui's
              // data-[state=open] / data-[state=closed] attributes.
              "transition-[opacity,transform,scale] duration-150",
              "data-[starting-style]:opacity-0 data-[starting-style]:scale-[0.98]",
              "data-[ending-style]:opacity-0 data-[ending-style]:scale-[0.98]",
              // Tabular numbers everywhere — every number in a tooltip
              // is comparing against another number, so the alignment
              // matters even at this small scale.
              "[&_*]:tabular-nums",
              popupClassName,
            )}
          >
            {content}
          </Tooltip.Popup>
        </Tooltip.Positioner>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}
