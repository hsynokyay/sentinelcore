"use client"

import * as React from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"

const SHORTCUTS: { keys: string; label: string }[] = [
  { keys: "⌘K", label: "Open command palette" },
  { keys: "?", label: "Show this overlay" },
  { keys: "G then F", label: "Go to Findings" },
  { keys: "G then R", label: "Go to Risks" },
  { keys: "G then S", label: "Go to Scans" },
  { keys: "G then D", label: "Go to Dashboard" },
]

export function KeyboardHelpOverlay({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
        </DialogHeader>
        <ul className="mt-4 space-y-2">
          {SHORTCUTS.map((s) => (
            <li key={s.keys} className="flex items-center justify-between text-body-sm">
              <span>{s.label}</span>
              <kbd className="rounded border border-border bg-surface-2 px-2 py-0.5 font-mono text-caption">
                {s.keys}
              </kbd>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  )
}
