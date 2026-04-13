import { InboxIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export interface EmptyStateProps {
  /** Main icon — shown above the title. Defaults to InboxIcon. */
  icon?: React.ReactNode;
  /** Primary headline. Short and descriptive ("No risks yet"). */
  title: string;
  /** Explanatory paragraph below the title. Up to two sentences. */
  description?: string;
  /** Optional hint below the description. Rendered in a smaller
   *  muted-italic style for guidance that's less important than the
   *  description ("Risks appear after the first scan completes."). */
  suggestion?: string;
  /** Primary CTA — renders below the text area. Pass a `<Button>`
   *  or a `<Link>` wrapper around a `<Button>`. */
  action?: React.ReactNode;
  /** Visual treatment:
   *  - `default` — open composition (no border, blends with page).
   *  - `card` — adds a subtle border + bg-card. Use inside cards or
   *    table wrappers where the empty state needs to feel contained. */
  variant?: "default" | "card";
  className?: string;
}

/**
 * EmptyState — a centered feedback template for when there's nothing
 * to render in a list, table, or panel.
 *
 * SentinelCore has two canonical empty-state scenarios:
 *
 *  1. **No data exists** — the project has never been scanned, or
 *     the entity type hasn't been created yet. The empty state should
 *     guide the user to the next step (run a scan, add a target, etc).
 *  2. **No data matches** — the entity type exists but the current
 *     filter / search excludes everything. The empty state should
 *     offer to broaden the filter.
 *
 * Both use this same template — the difference lives in the `title`,
 * `description`, `suggestion`, and `action` slots, which the consumer
 * fills in. Pre-built canonical configurations live in the feature
 * modules (e.g. `features/risks/risks-empty-state.tsx`).
 *
 * The icon defaults to `InboxIcon` because it's semantically neutral.
 * Feature-specific empty states should override it with a domain icon
 * (Shield for risks, Play for scans, etc.) so the empty state feels
 * like part of the feature rather than a generic fallback.
 */
export function EmptyState({
  icon,
  title,
  description,
  suggestion,
  action,
  variant = "default",
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center py-16 px-4 text-center",
        variant === "card" && "rounded-lg border bg-card",
        className,
      )}
    >
      <div className="text-muted-foreground mb-4">
        {icon || <InboxIcon className="h-12 w-12" />}
      </div>
      <h3 className="text-lg font-medium text-foreground">{title}</h3>
      {description && (
        <p className="mt-1 text-sm text-muted-foreground max-w-sm">
          {description}
        </p>
      )}
      {suggestion && (
        <p className="mt-2 text-xs italic text-muted-foreground/70 max-w-sm">
          {suggestion}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
