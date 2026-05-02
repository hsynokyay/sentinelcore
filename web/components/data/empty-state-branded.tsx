import * as React from "react"
import Link from "next/link"
import { type LucideIcon } from "lucide-react"
import { Button } from "@/components/ui/button"

interface EmptyStateBrandedProps {
  icon: LucideIcon
  title: string
  description?: string
  action?: { label: string; href?: string; onClick?: () => void }
}

export function EmptyStateBranded({ icon: Icon, title, description, action }: EmptyStateBrandedProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-brand-muted text-brand mb-4">
        <Icon className="size-5" />
      </div>
      <h3 className="text-h3 text-foreground">{title}</h3>
      {description && (
        <p className="text-body-sm text-muted-foreground mt-1 max-w-sm">{description}</p>
      )}
      {action && (
        <div className="mt-4">
          {action.href ? (
            <Button asChild>
              <Link href={action.href}>{action.label}</Link>
            </Button>
          ) : (
            <Button onClick={action.onClick}>{action.label}</Button>
          )}
        </div>
      )}
    </div>
  )
}
