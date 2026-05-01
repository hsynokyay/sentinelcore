"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  LayoutDashboard, Shield, AlertTriangle, Play, Target, KeyRound, FileArchive,
  Globe, CheckCircle, Bell, FileText, Settings,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { SidebarGroup } from "./sidebar-group"
import { WorkspaceSwitcher } from "./workspace-switcher"
import { useWorkspace } from "@/lib/workspace-context"

const groups = [
  {
    label: "Posture",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/findings", label: "Findings", icon: Shield },
      { href: "/risks", label: "Risks", icon: AlertTriangle },
    ],
  },
  {
    label: "Scanning",
    items: [
      { href: "/scans", label: "Scans", icon: Play },
      { href: "/targets", label: "Targets", icon: Target },
      { href: "/auth-profiles", label: "Auth Profiles", icon: KeyRound },
      { href: "/artifacts", label: "Source Artifacts", icon: FileArchive },
      { href: "/surface", label: "Attack Surface", icon: Globe },
    ],
  },
  {
    label: "Operations",
    items: [
      { href: "/approvals", label: "Approvals", icon: CheckCircle },
      { href: "/notifications", label: "Notifications", icon: Bell },
      { href: "/audit", label: "Audit Log", icon: FileText },
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
] as const

export function Sidebar() {
  const pathname = usePathname()
  const { activeProject } = useWorkspace()

  return (
    <aside className="w-60 shrink-0 border-r border-border bg-surface-1 flex flex-col h-full">
      <div className="p-3 border-b border-border">
        <WorkspaceSwitcher />
      </div>

      <nav className="flex-1 overflow-y-auto p-2">
        {groups.map((g) => (
          <SidebarGroup key={g.label} label={g.label}>
            {g.items.map((item) => {
              const active = pathname.startsWith(item.href)
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "group relative flex items-center gap-2.5 rounded-md px-3 py-1.5 text-body-sm transition-colors duration-fast focus-ring",
                    active
                      ? "relative bg-gradient-to-r from-brand/15 via-brand/8 to-transparent text-foreground font-medium before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[2px] before:rounded-full before:bg-brand"
                      : "text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                  )}
                >
                  <item.icon className={cn(
                    "size-4 shrink-0 transition-colors duration-fast",
                    active ? "text-brand" : "text-muted-foreground group-hover:text-foreground"
                  )} />
                  {item.label}
                </Link>
              )
            })}
          </SidebarGroup>
        ))}
      </nav>

      <div className="p-3 border-t border-border text-caption text-muted-foreground/70 space-y-1">
        <div className="truncate">{activeProject?.display_name ?? "—"}</div>
        <div>v0.1.0</div>
      </div>
    </aside>
  )
}
