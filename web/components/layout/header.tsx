"use client"

import { Bell } from "lucide-react"
import { Breadcrumbs } from "./breadcrumbs"
import { GlobalSearchTrigger } from "./global-search-trigger"
import { ThemeSwitcher } from "./theme-switcher"
import { UserMenu } from "./user-menu"
import { Button } from "@/components/ui/button"
import { PulseDot } from "@/components/security/pulse-dot"
import { useEmergencyStops } from "@/features/governance/hooks"

interface HeaderProps {
  onOpenCommandPalette?: () => void
}

export function Header({ onOpenCommandPalette }: HeaderProps) {
  const { data: stopsData } = useEmergencyStops()
  const hasActiveStops = (stopsData?.stops ?? []).length > 0

  return (
    <header className="h-14 border-b border-border bg-bg flex items-center gap-4 px-4">
      <div className="flex-1 min-w-0">
        <Breadcrumbs />
      </div>

      {onOpenCommandPalette && (
        <div className="hidden md:block flex-1 max-w-md">
          <GlobalSearchTrigger onOpen={onOpenCommandPalette} />
        </div>
      )}

      <div className="flex items-center gap-1.5 shrink-0">
        {hasActiveStops && (
          <span className="inline-flex items-center gap-1.5 rounded-md bg-[color:var(--severity-critical)]/12 px-2 py-1 text-caption text-[color:var(--severity-critical)]">
            <PulseDot tone="err" size="xs" aria-label="Emergency stop active" />
            ESTOP
          </span>
        )}
        <Button variant="ghost" size="icon" aria-label="Notifications" className="relative">
          <Bell className="size-4" />
          {hasActiveStops && (
            <span className="absolute top-1.5 right-1.5">
              <PulseDot tone="err" size="xs" aria-label="Unread alerts" />
            </span>
          )}
        </Button>
        <ThemeSwitcher />
        <UserMenu />
      </div>
    </header>
  )
}
