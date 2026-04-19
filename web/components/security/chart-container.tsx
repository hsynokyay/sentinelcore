"use client";

import { cn } from "@/lib/utils";

export interface ChartContainerProps {
  /** Card title — short, descriptive ("Severity distribution",
   *  "Risk score over time"). */
  title: string;
  /** Optional secondary line. Almost always a `<MicroInsight>` —
   *  the conclusion the chart is evidence for. */
  insight?: React.ReactNode;
  /** Optional right-aligned controls — legend, time-range picker,
   *  export button. Kept on the same row as the title to save vertical
   *  space, since charts already take up a lot of it. */
  actions?: React.ReactNode;
  /** The chart body. Hand-rolled SVG, a Recharts tree, a CSS-driven
   *  div composition — the container is unopinionated about what
   *  goes inside. */
  children: React.ReactNode;
  /** Optional footer for legends or annotations that don't fit in
   *  the header. */
  footer?: React.ReactNode;
  /** Optional skeleton-loading mode. Renders a shimmer block instead
   *  of the children, so the layout doesn't shift when data lands. */
  isLoading?: boolean;
  /** Approximate body height during loading, used for the shimmer
   *  block size. Defaults to 120px. */
  loadingHeight?: number;
  className?: string;
}

/**
 * ChartContainer — the standard chrome for any visualization in
 * SentinelCore. Provides a consistent header (title + optional
 * insight + optional actions), a body slot, and an optional footer.
 *
 * The container is intentionally minimal — it's a card with one
 * specific layout, not a config-heavy chart wrapper. The chart body
 * itself is rendered as `children`, so consumers can drop in any
 * SVG / CSS / library output without the container needing to know
 * about chart libraries.
 *
 * Header layout:
 *   ┌─────────────────────────────────┬───────────────┐
 *   │ Title                           │ [actions]     │
 *   │ Insight (MicroInsight or text)  │               │
 *   ├─────────────────────────────────┴───────────────┤
 *   │ children (chart body)                            │
 *   ├──────────────────────────────────────────────────┤
 *   │ footer (optional)                                │
 *   └──────────────────────────────────────────────────┘
 *
 * The "look first, count second" UX rule is enforced by the header
 * shape: title on top, insight directly below, then the chart. The
 * insight is the conclusion; the chart is the evidence. By the time
 * the operator's eye reaches the SVG, they already know what it says.
 */
export function ChartContainer({
  title,
  insight,
  actions,
  children,
  footer,
  isLoading = false,
  loadingHeight = 120,
  className,
}: ChartContainerProps) {
  return (
    <section
      className={cn("rounded-lg border bg-card p-4", className)}
      aria-label={title}
    >
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          {insight && <div className="mt-1">{insight}</div>}
        </div>
        {actions && <div className="shrink-0">{actions}</div>}
      </header>

      <div className="mt-4">
        {isLoading ? (
          <div
            className="w-full animate-pulse rounded bg-muted"
            style={{ height: loadingHeight }}
            aria-hidden="true"
          />
        ) : (
          children
        )}
      </div>

      {footer && (
        <footer className="mt-4 border-t pt-3 text-xs text-muted-foreground">
          {footer}
        </footer>
      )}
    </section>
  );
}
