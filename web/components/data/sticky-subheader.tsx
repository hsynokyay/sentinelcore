"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

export function StickySubheader({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        "sticky top-0 z-20 -mx-6 px-6 py-2 bg-bg/85 backdrop-blur-md border-b border-border-subtle",
        className
      )}
    >
      {children}
    </div>
  )
}
