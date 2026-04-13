"use client";

import { cn } from "@/lib/utils";
import { DeltaChip, type DeltaPolarity } from "./delta-chip";
import { severityTextClass, severityBgClass } from "@/lib/security/intensity";
import type { RiskSeverity } from "@/lib/types";

// ─── Caption modes ──────────────────────────────────────────────────

/** Delta caption — a signed change chip ("+ 5 this week"). */
export interface DeltaCaption {
  mode: "delta";
  value: number;
  label?: string;
  polarity?: DeltaPolarity;
}

/** Breakdown caption — severity-segment mini-bar with counts. */
export interface BreakdownCaption {
  mode: "breakdown";
  segments: { severity: RiskSeverity; count: number }[];
}

/** Top-class caption — the dominant category in this tile's set. */
export interface TopClassCaption {
  mode: "top-class";
  /** e.g. "SQL injection", "Open redirect" */
  className: string;
  /** What fraction this class represents, e.g. "4 of 7" */
  share?: string;
}

export type TileCaption = DeltaCaption | BreakdownCaption | TopClassCaption;

// ─── SummaryTile ────────────────────────────────────────────────────

/**
 * One stat tile in a ChangeSummaryStrip. Each tile shows:
 *  - a small uppercase eyebrow `label`
 *  - a focal `value` (number or pre-formatted string)
 *  - an optional caption area below the value (delta, breakdown, or
 *    top-class mode)
 *  - an optional severity tint that re-colours the value
 */
export interface SummaryTile {
  /** Eyebrow text. Rendered uppercase + tracking-wide. Keep it short
   *  ("ACTIVE", "CRITICAL", "ADDED THIS WEEK"). */
  label: string;
  /** The focal number. Numbers render with `tabular-nums` for alignment;
   *  pass a pre-formatted string for non-numeric tiles ("∞", "—", etc). */
  value: number | string;
  /** Rich caption rendered below the focal value. Three modes:
   *  - `delta`     — signed change chip ("+5 this week")
   *  - `breakdown` — severity-segment mini-bar (4 critical, 3 high)
   *  - `top-class` — dominant vuln class ("Mostly SQL injection")
   *
   *  When omitted, falls back to the legacy `delta` shorthand below. */
  caption?: TileCaption;
  /** Legacy shorthand — equivalent to `caption: { mode: "delta", ...delta }`.
   *  Kept for backwards compat so existing callers (risk-stats, etc.)
   *  don't need to change. If both `caption` and `delta` are set,
   *  `caption` wins. */
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

  // Resolve caption: explicit `caption` wins, then legacy `delta` shorthand.
  const resolvedCaption: TileCaption | undefined = tile.caption
    ? tile.caption
    : tile.delta
      ? { mode: "delta", ...tile.delta }
      : undefined;

  return (
    <article className="rounded-lg border bg-card p-3">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        {tile.label}
      </p>
      {isLoading ? (
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
      {resolvedCaption && !isLoading && (
        <div className="mt-2">
          <TileCaptionRenderer caption={resolvedCaption} />
        </div>
      )}
    </article>
  );
}

// ─── Caption renderers ──────────────────────────────────────────────

function TileCaptionRenderer({ caption }: { caption: TileCaption }) {
  switch (caption.mode) {
    case "delta":
      return (
        <DeltaChip
          value={caption.value}
          label={caption.label}
          polarity={caption.polarity}
        />
      );
    case "breakdown":
      return <BreakdownBar segments={caption.segments} />;
    case "top-class":
      return <TopClassLabel className={caption.className} share={caption.share} />;
  }
}

/**
 * Breakdown mini-bar — renders severity segments as coloured spans in a
 * single-line flex row. Each segment is proportional to its count. Below
 * the bar, the top two non-zero counts are listed as text.
 */
function BreakdownBar({
  segments,
}: {
  segments: { severity: RiskSeverity; count: number }[];
}) {
  const total = segments.reduce((sum, s) => sum + s.count, 0);
  const nonZero = segments.filter((s) => s.count > 0);
  if (total === 0) {
    return (
      <span className="text-[10px] text-muted-foreground">No breakdown</span>
    );
  }

  return (
    <div className="space-y-1">
      {/* Mini-bar */}
      <div
        className="flex h-1.5 w-full overflow-hidden rounded-full bg-[var(--contrib-track)]"
        aria-hidden="true"
      >
        {nonZero.map((seg) => (
          <div
            key={seg.severity}
            className={cn("h-full", severityBgClass(seg.severity))}
            style={{ width: `${(seg.count / total) * 100}%` }}
          />
        ))}
      </div>
      {/* Top 2 labels */}
      <p className="text-[10px] text-muted-foreground leading-tight truncate">
        {nonZero
          .slice(0, 2)
          .map((s) => `${s.count} ${s.severity}`)
          .join(" · ")}
      </p>
    </div>
  );
}

/**
 * Top-class label — a compact sentence naming the dominant vuln class.
 * E.g. "Mostly SQL injection · 4 of 7"
 */
function TopClassLabel({
  className,
  share,
}: {
  className: string;
  share?: string;
}) {
  return (
    <p className="text-[10px] text-muted-foreground leading-tight truncate">
      <span className="text-foreground/80">{className}</span>
      {share && <span className="ml-1 opacity-60">· {share}</span>}
    </p>
  );
}
