"use client"

import * as React from "react"
import { cn } from "@/lib/utils"
import { Sparkline } from "./sparkline"

interface HeroStatProps {
  label: string
  /** Pre-formatted display value (e.g. "1,247", "98.2%"). */
  value: string | number
  /** Optional change indicator (e.g. "+12 this week"). */
  delta?: { text: string; tone: "positive" | "negative" | "neutral" }
  /** Optional sparkline data (last N points). */
  sparkline?: number[]
  /** Tone for the soft accent halo around the card. */
  tone?: "brand" | "critical" | "warning" | "success"
  /** Inline icon rendered before the label. */
  icon?: React.ReactNode
  className?: string
}

const haloClass = {
  brand: "bg-gradient-to-br from-brand/8 via-transparent to-transparent",
  critical: "bg-gradient-to-br from-[color:var(--severity-critical)]/8 via-transparent to-transparent",
  warning: "bg-gradient-to-br from-[color:var(--severity-medium)]/8 via-transparent to-transparent",
  success: "bg-gradient-to-br from-[color:var(--signal-new)]/8 via-transparent to-transparent",
} as const

const deltaToneClass = {
  positive: "text-[color:var(--signal-new)]",
  negative: "text-[color:var(--severity-critical)]",
  neutral: "text-muted-foreground",
} as const

export function HeroStat({
  label,
  value,
  delta,
  sparkline,
  tone = "brand",
  icon,
  className,
}: HeroStatProps) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-xl border border-border bg-surface-1 p-5 transition-colors duration-fast hover:border-border-strong",
        className
      )}
    >
      <div className={cn("absolute inset-0 pointer-events-none opacity-80", haloClass[tone])} aria-hidden="true" />

      <div className="relative flex items-center justify-between gap-2 mb-3">
        <div className="inline-flex items-center gap-1.5 text-caption text-muted-foreground">
          {icon}
          <span>{label}</span>
        </div>
      </div>

      <div className="relative flex items-end justify-between gap-3">
        <div>
          <div className="font-display text-stat-num text-foreground">{value}</div>
          {delta && (
            <div className={cn("mt-1.5 text-body-sm tabular-nums", deltaToneClass[delta.tone])}>
              {delta.text}
            </div>
          )}
        </div>
        {sparkline && sparkline.length > 1 && (
          <div className="shrink-0">
            <Sparkline
              data={sparkline}
              width={80}
              height={32}
              tone={delta?.tone === "negative" ? "negative" : delta?.tone === "positive" ? "positive" : "neutral"}
            />
          </div>
        )}
      </div>
    </div>
  )
}
