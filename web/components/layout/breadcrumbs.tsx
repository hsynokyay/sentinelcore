"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { ChevronRight } from "lucide-react"
import { labelForSegment } from "@/lib/route-labels"

export function Breadcrumbs() {
  const pathname = usePathname()
  const segments = pathname.split("/").filter(Boolean)
  if (segments.length === 0) return null

  const crumbs = segments.map((seg, i) => ({
    label: labelForSegment(seg),
    href: "/" + segments.slice(0, i + 1).join("/"),
    isLast: i === segments.length - 1,
  }))

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-body-sm">
      {crumbs.map((c, i) => (
        <span key={c.href} className="flex items-center gap-1">
          {i > 0 && <ChevronRight className="size-3.5 text-muted-foreground/50" />}
          {c.isLast ? (
            <span className="text-foreground truncate max-w-[200px]">{c.label}</span>
          ) : (
            <Link
              href={c.href}
              className="text-muted-foreground hover:text-foreground transition-colors duration-fast focus-ring rounded-sm"
            >
              {c.label}
            </Link>
          )}
        </span>
      ))}
    </nav>
  )
}
