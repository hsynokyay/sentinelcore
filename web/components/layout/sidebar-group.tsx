"use client"

import * as React from "react"
import { ChevronDown } from "lucide-react"
import { cn } from "@/lib/utils"

export function SidebarGroup({
  label,
  defaultOpen = true,
  children,
}: {
  label: string
  defaultOpen?: boolean
  children: React.ReactNode
}) {
  const [open, setOpen] = React.useState(defaultOpen)
  return (
    <div className="mb-2">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-3 py-1.5 text-caption text-muted-foreground/80 hover:text-foreground transition-colors duration-fast focus-ring rounded-sm"
      >
        <span>{label}</span>
        <ChevronDown
          className={cn(
            "size-3 transition-transform duration-fast",
            !open && "-rotate-90"
          )}
        />
      </button>
      {open && <div className="space-y-0.5 mt-1">{children}</div>}
    </div>
  )
}
