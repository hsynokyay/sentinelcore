"use client";

import { Bell, LogOut, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/features/auth/hooks";
import { useEmergencyStops } from "@/features/governance/hooks";

export function Header() {
  const { user, logout } = useAuth();
  const { data: stopsData } = useEmergencyStops();
  const hasActiveStops = (stopsData?.stops ?? []).length > 0;

  return (
    <header className="h-14 border-b bg-card flex items-center justify-between px-6">
      <div>
        {hasActiveStops && (
          <span className="inline-flex items-center gap-1.5 rounded-md bg-destructive/15 px-2 py-0.5 text-xs font-semibold text-destructive">
            ESTOP
          </span>
        )}
      </div>
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-4 w-4" />
          {hasActiveStops && (
            <span className="absolute top-1 right-1 h-2 w-2 rounded-full bg-destructive" />
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
