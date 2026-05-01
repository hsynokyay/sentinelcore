"use client"

import * as React from "react"
import { ChevronsUpDown, Check, ShieldCheck } from "lucide-react"
import * as Popover from "@base-ui/react/popover"
import { useWorkspace } from "@/lib/workspace-context"
import { cn } from "@/lib/utils"

export function WorkspaceSwitcher() {
  const { projects, projectId, setProjectId, activeProject } = useWorkspace()
  const [open, setOpen] = React.useState(false)

  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger
        className="flex h-10 w-full items-center gap-2 rounded-md border border-border bg-surface-1 px-2 text-left text-body-sm hover:bg-surface-2 transition-colors duration-fast focus-ring"
      >
        <ShieldCheck className="size-4 text-brand shrink-0" />
        <div className="flex-1 truncate">
          <div className="text-body-sm font-medium text-foreground truncate">
            {activeProject?.display_name ?? activeProject?.name ?? "Select project"}
          </div>
        </div>
        <ChevronsUpDown className="size-4 text-muted-foreground shrink-0" />
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Positioner sideOffset={4} align="start">
          <Popover.Popup
            className="z-50 w-[224px] rounded-md border border-border bg-surface-2 p-1 shadow-xl"
          >
            {projects.length === 0 ? (
              <div className="px-2 py-3 text-body-sm text-muted-foreground">
                No projects available
              </div>
            ) : (
              projects.map((p) => (
                <button
                  key={p.id}
                  onClick={() => {
                    setProjectId(p.id)
                    setOpen(false)
                  }}
                  className={cn(
                    "flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-body-sm hover:bg-surface-3 transition-colors duration-fast focus-ring",
                    p.id === projectId && "bg-surface-3"
                  )}
                >
                  <span className="flex-1 truncate">{p.display_name ?? p.name}</span>
                  {p.id === projectId && <Check className="size-3.5 text-brand" />}
                </button>
              ))
            )}
          </Popover.Popup>
        </Popover.Positioner>
      </Popover.Portal>
    </Popover.Root>
  )
}
