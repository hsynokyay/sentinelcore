"use client"

import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-1.5 h-5 text-[11px] font-medium tabular-nums [&>svg]:size-3 [&>svg]:shrink-0",
  {
    variants: {
      variant: {
        severity: "border-transparent",
        status: "border-transparent",
        tag: "border-border bg-surface-2 text-muted-foreground",
        outline: "border-border bg-transparent text-foreground",
      },
      tone: {
        critical: "bg-[color:var(--severity-critical)]/12 text-[color:var(--severity-critical)]",
        high: "bg-[color:var(--severity-high)]/12 text-[color:var(--severity-high)]",
        medium: "bg-[color:var(--severity-medium)]/12 text-[color:var(--severity-medium)]",
        low: "bg-[color:var(--severity-low)]/12 text-[color:var(--severity-low)]",
        info: "bg-[color:var(--severity-info)]/12 text-[color:var(--severity-info)]",
        success: "bg-[color:var(--signal-new)]/12 text-[color:var(--signal-new)]",
        warning: "bg-[color:var(--severity-medium)]/12 text-[color:var(--severity-medium)]",
        error: "bg-[color:var(--severity-critical)]/12 text-[color:var(--severity-critical)]",
        neutral: "bg-surface-2 text-muted-foreground",
      },
    },
    defaultVariants: { variant: "tag", tone: "neutral" },
  }
)

interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, tone, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant, tone }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
