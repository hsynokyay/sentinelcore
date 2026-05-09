"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

interface HeatmapCell {
  /** ISO week-day (0 = Sun … 6 = Sat) */
  day: number
  /** 0–23 hour-of-day */
  hour: number
  /** Count of items in this slot. */
  count: number
}

interface SeverityHeatmapProps {
  cells: HeatmapCell[]
  className?: string
}

const dayLabels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

export function SeverityHeatmap({ cells, className }: SeverityHeatmapProps) {
  const max = Math.max(1, ...cells.map((c) => c.count))
  const grid = React.useMemo(() => {
    const out: number[][] = Array.from({ length: 7 }, () => Array(24).fill(0))
    for (const c of cells) out[c.day]![c.hour] = c.count
    return out
  }, [cells])

  return (
    <div className={cn("flex gap-1.5", className)}>
      <div className="flex flex-col justify-between text-caption text-muted-foreground/70 py-px">
        {dayLabels.map((d, i) => (
          <span key={i} className="leading-none">{d.slice(0, 1)}</span>
        ))}
      </div>
      <div className="grid grid-cols-24 gap-px flex-1" style={{ gridTemplateColumns: "repeat(24, minmax(0, 1fr))" }}>
        {grid.flatMap((row, di) =>
          row.map((count, hi) => {
            const intensity = count / max
            return (
              <div
                key={`${di}-${hi}`}
                className="aspect-square rounded-[2px]"
                style={{
                  backgroundColor:
                    count === 0
                      ? "var(--surface-2)"
                      : `oklch(from var(--severity-critical) l c h / ${0.15 + intensity * 0.85})`,
                }}
                title={`${dayLabels[di]} ${hi}:00 — ${count} findings`}
                aria-label={`${dayLabels[di]} ${hi}:00 — ${count} findings`}
              />
            )
          })
        )}
      </div>
    </div>
  )
}
