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
      // Tone backgrounds use 20% alpha (was 12%). At 12%, the tinted fill
      // washed out against the row hover background (surface-2), making
      // badges appear empty. 20% keeps the fill readable on every surface
      // (bg, surface-1, surface-2, surface-3) without becoming saturated.
      // Border on tone variants matches the text color at 30% alpha so
      // the pill shape stays visible even on hover.
      tone: {
        critical: "bg-[color:var(--severity-critical)]/20 text-[color:var(--severity-critical)] border-[color:var(--severity-critical)]/30",
        high: "bg-[color:var(--severity-high)]/20 text-[color:var(--severity-high)] border-[color:var(--severity-high)]/30",
        medium: "bg-[color:var(--severity-medium)]/20 text-[color:var(--severity-medium)] border-[color:var(--severity-medium)]/30",
        low: "bg-[color:var(--severity-low)]/20 text-[color:var(--severity-low)] border-[color:var(--severity-low)]/30",
        info: "bg-[color:var(--severity-info)]/20 text-[color:var(--severity-info)] border-[color:var(--severity-info)]/30",
        success: "bg-[color:var(--signal-new)]/20 text-[color:var(--signal-new)] border-[color:var(--signal-new)]/30",
        warning: "bg-[color:var(--severity-medium)]/20 text-[color:var(--severity-medium)] border-[color:var(--severity-medium)]/30",
        error: "bg-[color:var(--severity-critical)]/20 text-[color:var(--severity-critical)] border-[color:var(--severity-critical)]/30",
        neutral: "bg-surface-2 text-muted-foreground border-border",
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
