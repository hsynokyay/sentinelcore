"use client"

import { Search } from "lucide-react"

export function GlobalSearchTrigger({ onOpen }: { onOpen: () => void }) {
  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label="Open command palette"
      className="hidden md:flex items-center gap-2 h-9 w-full max-w-md rounded-md border border-border bg-surface-1 px-3 text-body-sm text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors duration-fast focus-ring"
    >
      <Search className="size-4 shrink-0" aria-hidden="true" />
      <span className="flex-1 text-left">Search or jump to…</span>
      <kbd className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
        ⌘K
      </kbd>
    </button>
  )
}
