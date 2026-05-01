"use client";

import { useAuth } from "@/features/auth/hooks";
import { AppShell } from "@/components/layout/app-shell";
import { useRouter, usePathname } from "next/navigation";
import { useEffect } from "react";
import { Loader2 } from "lucide-react";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push("/login");
    }
  }, [isLoading, isAuthenticated, router]);

  // Defensive: clear any leftover Base UI / Floating UI inert markers on every
  // route change. If a dialog (Base UI or transitive Radix from cmdk) leaked
  // `inert` / `aria-hidden` onto outside elements, the sidebar becomes
  // unclickable and the user can't navigate. Clearing on pathname change is
  // belt-and-braces — Base UI's own cleanup should already have run.
  useEffect(() => {
    document.querySelectorAll<HTMLElement>("[data-base-ui-inert]").forEach((el) => {
      el.removeAttribute("inert");
      if (el.getAttribute("aria-hidden") === "true") {
        el.removeAttribute("aria-hidden");
      }
      el.removeAttribute("data-base-ui-inert");
    });
    document.documentElement.removeAttribute("data-base-ui-scroll-locked");
  }, [pathname]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!isAuthenticated) return null;

  return <AppShell>{children}</AppShell>;
}
