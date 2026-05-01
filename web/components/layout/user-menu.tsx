"use client"

import * as React from "react"
import { LogOut, Settings } from "lucide-react"
import * as Popover from "@base-ui/react/popover"
import Link from "next/link"
import { useAuth } from "@/features/auth/hooks"

export function UserMenu() {
  const { user, logout } = useAuth()
  const [open, setOpen] = React.useState(false)
  const displayName = user?.full_name || user?.email || "User"
  const initials = displayName.slice(0, 2).toUpperCase()

  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger
        aria-label="User menu"
        className="flex items-center gap-2 h-9 px-1 rounded-md hover:bg-surface-2 transition-colors duration-fast focus-ring"
      >
        <div className="flex size-7 items-center justify-center rounded-full bg-brand-muted text-brand text-[11px] font-semibold">
          {initials}
        </div>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Positioner sideOffset={6} align="end">
          <Popover.Popup className="z-50 w-56 rounded-md border border-border bg-surface-2 p-1 shadow-xl">
            <div className="px-2.5 py-2 border-b border-border-subtle">
              <div className="text-body-sm font-medium text-foreground truncate">
                {displayName}
              </div>
              <div className="text-caption text-muted-foreground mt-0.5">
                {user?.role}
              </div>
            </div>
            <div className="p-1">
              <Link
                href="/settings"
                className="flex items-center gap-2 rounded-sm px-2 py-1.5 text-body-sm hover:bg-surface-3 focus-ring"
                onClick={() => setOpen(false)}
              >
                <Settings className="size-3.5 text-muted-foreground" />
                Settings
              </Link>
              <button
                onClick={() => { setOpen(false); void logout() }}
                className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-body-sm hover:bg-surface-3 focus-ring"
              >
                <LogOut className="size-3.5 text-muted-foreground" />
                Sign out
              </button>
            </div>
          </Popover.Popup>
        </Popover.Positioner>
      </Popover.Portal>
    </Popover.Root>
  )
}
