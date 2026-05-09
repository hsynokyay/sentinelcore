"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

type Severity = "critical" | "high" | "medium" | "low" | "info"

interface StackedBarProps {
  segments: { severity: Severity; count: number }[]
  height?: number
  className?: string
}

const severityVar: Record<Severity, string> = {
  critical: "--severity-critical",
  high: "--severity-high",
  medium: "--severity-medium",
  low: "--severity-low",
  info: "--severity-info",
}

const severityLabel: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
}

export function StackedBar({ segments, height = 8, className }: StackedBarProps) {
  const total = segments.reduce((s, x) => s + x.count, 0)
  if (total === 0) {
    return (
      <div
        className={cn("w-full rounded-full bg-surface-2", className)}
        style={{ height }}
        aria-label="No findings"
      />
    )
  }
  return (
    <div
      className={cn("flex w-full overflow-hidden rounded-full bg-surface-2", className)}
      style={{ height }}
      role="img"
      aria-label={`Severity distribution: ${segments
        .map((s) => `${s.count} ${severityLabel[s.severity]}`)
        .join(", ")}`}
    >
      {segments.map((s) => {
        const pct = (s.count / total) * 100
        if (pct === 0) return null
        return (
          <div
            key={s.severity}
            style={{
              width: `${pct}%`,
              backgroundColor: `var(${severityVar[s.severity]})`,
            }}
            title={`${severityLabel[s.severity]}: ${s.count}`}
          />
        )
      })}
    </div>
  )
}
