"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, Shield, Play, Globe, CheckCircle, Bell, FileText, Settings, ShieldCheck, Target, KeyRound, FileArchive, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/findings", label: "Findings", icon: Shield },
  { href: "/risks", label: "Risks", icon: AlertTriangle },
  { href: "/scans", label: "Scans", icon: Play },
  { href: "/targets", label: "Targets", icon: Target },
  { href: "/auth-profiles", label: "Auth Profiles", icon: KeyRound },
  { href: "/artifacts", label: "Source Artifacts", icon: FileArchive },
  { href: "/surface", label: "Attack Surface", icon: Globe },
  { href: "/approvals", label: "Approvals", icon: CheckCircle },
  { href: "/notifications", label: "Notifications", icon: Bell },
  { href: "/audit", label: "Audit Log", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-56 border-r bg-card flex flex-col h-full">
      <div className="p-4 border-b">
        <Link href="/findings" className="flex items-center gap-2 font-semibold text-lg">
          <ShieldCheck className="h-6 w-6 text-primary" />
          <span>SentinelCore</span>
        </Link>
      </div>
      <nav className="flex-1 p-2 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2 text-sm rounded-md transition-colors",
                isActive
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="p-4 border-t text-xs text-muted-foreground">
        SentinelCore v0.1.0
      </div>
    </aside>
  );
}
