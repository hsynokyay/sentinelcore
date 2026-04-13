"use client";

import { cn } from "@/lib/utils";
import { DeltaChip, type DeltaPolarity } from "./delta-chip";
import { severityTextClass } from "@/lib/security/intensity";
import type { RiskSeverity } from "@/lib/types";

/**
 * One stat tile in a ChangeSummaryStrip. Each tile shows:
 *  - a small uppercase eyebrow `label`
 *  - a focal `value` (number or pre-formatted string)
 *  - an optional `delta` chip (with its own polarity)
 *  - an optional severity tint that re-colours the value
 */
export interface SummaryTile {
  /** Eyebrow text. Rendered uppercase + tracking-wide. Keep it short
   *  ("ACTIVE", "CRITICAL", "ADDED THIS WEEK"). */
  label: string;
  /** The focal number. Numbers render with `tabular-nums` for alignment;
   *  pass a pre-formatted string for non-numeric tiles ("∞", "—", etc). */
  value: number | string;
  /** Optional delta — appears as a small DeltaChip below the value. */
  delta?: {
    value: number;
    label?: string;
    polarity?: DeltaPolarity;
  };
  /** Optional severity tint applied to the focal number. Use this for
   *  segment tiles like "CRITICAL" / "HIGH" so the colour reinforces the
   *  meaning without needing extra chrome. */
  emphasis?: RiskSeverity;
  /** Stable identity for React's reconciler. Defaults to label, but pass
   *  one explicitly if you might have two tiles with the same label. */
  id?: string;
}

export interface ChangeSummaryStripProps {
  tiles: SummaryTile[];
  /** Skeleton state — renders ghost tiles instead of values, so the
   *  layout doesn't shift when the data lands. */
  isLoading?: boolean;
  className?: string;
}

/**
 * ChangeSummaryStrip — a horizontal strip of bordered stat tiles that
 * sits at the top of a list page (or a dashboard section) and gives the
 * user the bird's-eye view of "what's the state and what's changed".
 *
 * Layout: a 1D grid that wraps to two rows on narrow viewports. Each
 * tile is a self-contained card with the same calm-by-default styling
 * the rest of the security surface uses — no decorative chrome,
 * tabular-nums numerals, severity tints earned only on segment tiles.
 *
 * The strip is presentational only — it does not fetch data, compute
 * deltas, or apply business logic. The consumer hands it `tiles` and
 * the strip renders. This keeps the same primitive useful for the
 * /risks page, the /findings page, and the dashboard without each
 * consumer dragging in unrelated logic.
 */
export function ChangeSummaryStrip({
  tiles,
  isLoading = false,
  className,
}: ChangeSummaryStripProps) {
  return (
    <section
      aria-label="Change summary"
      className={cn(
        // Auto-fit grid: tiles claim a minimum width and wrap to a new
        // row when the viewport can't hold them. minmax(160px, 1fr)
        // means each tile is at least 160px wide and stretches to fill
        // its slice of the available width.
        "grid grid-cols-[repeat(auto-fit,minmax(160px,1fr))] gap-3",
        className,
      )}
    >
      {tiles.map((tile) => (
        <SummaryTileCard
          key={tile.id ?? tile.label}
          tile={tile}
          isLoading={isLoading}
        />
      ))}
    </section>
  );
}

/**
 * Render one tile. Extracted so the loop above stays a single
 * expression and so React DevTools shows a meaningful frame.
 */
function SummaryTileCard({
  tile,
  isLoading,
}: {
  tile: SummaryTile;
  isLoading: boolean;
}) {
  const numberColour = tile.emphasis
    ? severityTextClass(tile.emphasis)
    : "text-foreground";

  return (
    <article className="rounded-lg border bg-card p-3">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        {tile.label}
      </p>
      {isLoading ? (
        // Ghost tile: a single muted bar at the same vertical position
        // as the real number, so the layout doesn't pop when data lands.
        <div
          className="mt-1 h-7 w-12 animate-pulse rounded bg-muted"
          aria-hidden="true"
        />
      ) : (
        <p
          className={cn(
            "mt-1 text-2xl font-bold leading-none tabular-nums",
            numberColour,
          )}
        >
          {tile.value}
        </p>
      )}
      {tile.delta && !isLoading && (
        <div className="mt-2">
          <DeltaChip
            value={tile.delta.value}
            label={tile.delta.label}
            polarity={tile.delta.polarity}
          />
        </div>
      )}
    </article>
  );
}
