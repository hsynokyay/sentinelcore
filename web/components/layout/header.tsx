"use client";

import { Bell, LogOut, Search, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PulseDot } from "@/components/security/pulse-dot";
import { useAuth } from "@/features/auth/hooks";
import { useEmergencyStops } from "@/features/governance/hooks";

interface HeaderProps {
  /** Open the global command palette. Wired up by AppShell — see
   *  the inline keyboard listener there for the Cmd+K binding. The
   *  prop exists so the search-button hint in the header can also
   *  open the palette by click for users who don't know the shortcut. */
  onOpenCommandPalette?: () => void;
}

export function Header({ onOpenCommandPalette }: HeaderProps) {
  const { user, logout } = useAuth();
  const { data: stopsData } = useEmergencyStops();
  const hasActiveStops = (stopsData?.stops ?? []).length > 0;

  return (
    <header className="h-14 border-b bg-card flex items-center justify-between px-6">
      <div className="flex items-center gap-2">
        {hasActiveStops ? (
          // ESTOP active — chip uses the err pulse to draw attention.
          // The dot pulses regardless of viewport focus, so an operator
          // glancing at the header sees motion before they read the label.
          <span className="inline-flex items-center gap-1.5 rounded-md bg-destructive/15 px-2 py-0.5 text-xs font-semibold text-destructive">
            <PulseDot tone="err" size="xs" aria-label="Emergency stop active" />
            ESTOP
          </span>
        ) : (
          // No active stops — quietly signal that the system is operational.
          // The dot is small (xs) and uses the calm "ok" pulse so the header
          // feels alive without competing with the page content.
          <span
            className="inline-flex items-center gap-1.5 text-xs text-muted-foreground"
            title="System operational"
          >
            <PulseDot tone="ok" size="xs" aria-label="System operational" />
            <span className="sr-only">System operational</span>
          </span>
        )}
      </div>
      <div className="flex items-center gap-3">
        {/* Command palette discoverability hint. Click to open the
            palette for users who don't know the Cmd+K shortcut; the
            ⌘K kbd tag teaches the shortcut for next time. */}
        {onOpenCommandPalette && (
          <button
            type="button"
            onClick={onOpenCommandPalette}
            className="hidden md:inline-flex h-8 items-center gap-2 rounded-md border bg-background px-2 text-xs text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
            aria-label="Open command palette"
          >
            <Search aria-hidden="true" className="size-3.5" />
            <span>Search…</span>
            <kbd className="rounded border bg-muted px-1.5 py-0.5 font-mono text-[10px]">
              ⌘K
            </kbd>
          </button>
        )}
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-4 w-4" />
          {hasActiveStops && (
            <span className="absolute top-1 right-1">
              <PulseDot tone="err" size="xs" aria-label="Unread alerts" />
            </span>
          )}
        </Button>
        <div className="flex items-center gap-2 text-sm">
          <div className="h-7 w-7 rounded-full bg-primary/10 flex items-center justify-center">
            <User className="h-4 w-4 text-primary" />
          </div>
          <span className="text-muted-foreground">{user?.full_name || user?.email || "User"}</span>
        </div>
        <Button variant="ghost" size="icon" onClick={logout}>
          <LogOut className="h-4 w-4" />
        </Button>
      </div>
    </header>
  );
}
