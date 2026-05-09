import * as React from "react"
import { cn } from "@/lib/utils"

interface DetailShellProps {
  leftRail: React.ReactNode
  main: React.ReactNode
  rightRail?: React.ReactNode
  className?: string
}

export function DetailShell({ leftRail, main, rightRail, className }: DetailShellProps) {
  return (
    <div
      className={cn(
        "grid gap-6",
        rightRail
          ? "grid-cols-[240px_1fr_320px]"
          : "grid-cols-[240px_1fr]",
        className
      )}
    >
      <aside className="space-y-4 text-body-sm">{leftRail}</aside>
      <div className="min-w-0">{main}</div>
      {rightRail && <aside className="space-y-4">{rightRail}</aside>}
    </div>
  )
}
