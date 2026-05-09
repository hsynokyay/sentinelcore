import * as React from "react"
import { cn } from "@/lib/utils"

interface PageHeaderProps {
  title: string
  description?: string
  /** Inline count next to the title (e.g. "1,247"). Optional. */
  count?: number | string
  /** Filter chips row (e.g. severity, status pickers). Renders below title. */
  filters?: React.ReactNode
  /** Right-aligned action buttons. */
  actions?: React.ReactNode
  className?: string
}

export function PageHeader({
  title,
  description,
  count,
  filters,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn("pb-4 border-b border-border-subtle mb-5", className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-baseline gap-2">
            <h1 className="text-h1 text-foreground">{title}</h1>
            {count !== undefined && (
              <span className="text-body-sm text-muted-foreground tabular">
                ({typeof count === "number" ? count.toLocaleString() : count})
              </span>
            )}
          </div>
          {description && (
            <p className="text-body-sm text-muted-foreground mt-1">{description}</p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
      </div>
      {filters && <div className="mt-3 flex items-center gap-2 flex-wrap">{filters}</div>}
    </div>
  )
}
