"use client"

import { Rows3, Rows4 } from "lucide-react"
import { useDensity } from "@/lib/density-context"
import { cn } from "@/lib/utils"

export function DensityToggle() {
  const { density, setDensity } = useDensity()
  return (
    <div className="inline-flex items-center rounded-md border border-border bg-surface-1 p-0.5">
      <button
        type="button"
        aria-label="Comfortable density"
        onClick={() => setDensity("comfortable")}
        className={cn(
          "flex size-7 items-center justify-center rounded-sm transition-colors duration-fast focus-ring",
          density === "comfortable" ? "bg-surface-3 text-foreground" : "text-muted-foreground hover:text-foreground"
        )}
      >
        <Rows3 className="size-3.5" />
      </button>
      <button
        type="button"
        aria-label="Compact density"
        onClick={() => setDensity("compact")}
        className={cn(
          "flex size-7 items-center justify-center rounded-sm transition-colors duration-fast focus-ring",
          density === "compact" ? "bg-surface-3 text-foreground" : "text-muted-foreground hover:text-foreground"
        )}
      >
        <Rows4 className="size-3.5" />
      </button>
    </div>
  )
}
