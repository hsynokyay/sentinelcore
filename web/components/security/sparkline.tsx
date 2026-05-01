"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

interface SparklineProps {
  data: number[]
  width?: number
  height?: number
  tone?: "neutral" | "positive" | "negative"
  className?: string
}

const toneClass = {
  neutral: "text-muted-foreground",
  positive: "text-[color:var(--signal-new)]",
  negative: "text-[color:var(--severity-critical)]",
} as const

export function Sparkline({
  data,
  width = 60,
  height = 24,
  tone = "neutral",
  className,
}: SparklineProps) {
  const path = React.useMemo(() => {
    if (data.length < 2) return ""
    const min = Math.min(...data)
    const max = Math.max(...data)
    const range = max - min || 1
    const stepX = width / (data.length - 1)
    return data
      .map((v, i) => {
        const x = i * stepX
        const y = height - ((v - min) / range) * height
        return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`
      })
      .join(" ")
  }, [data, width, height])

  if (data.length < 2) {
    return <div className={cn("inline-block", className)} style={{ width, height }} aria-hidden="true" />
  }
  return (
    <svg
      className={cn("inline-block", toneClass[tone], className)}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden="true"
    >
      <path d={path} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
