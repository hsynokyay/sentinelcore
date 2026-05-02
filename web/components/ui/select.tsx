"use client"

import * as React from "react"
import { Select as SelectPrimitive } from "@base-ui/react/select"
import { ChevronDown, Check } from "lucide-react"

import { cn } from "@/lib/utils"

function Select({
  value,
  onValueChange,
  disabled,
  children,
  ...props
}: Omit<React.ComponentProps<typeof SelectPrimitive.Root>, "onValueChange"> & {
  onValueChange?: (value: string) => void;
  disabled?: boolean;
}) {
  return (
    <SelectPrimitive.Root
      value={value}
      onValueChange={onValueChange ? (v) => { if (v != null) onValueChange(String(v)); } : undefined}
      disabled={disabled}
      {...props}
    >
      {children}
    </SelectPrimitive.Root>
  )
}

function SelectTrigger({
  className,
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Trigger>) {
  return (
    <SelectPrimitive.Trigger
      className={cn(
        "flex h-8 w-full items-center justify-between rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 dark:bg-input/30",
        className
      )}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon>
        <ChevronDown className="h-4 w-4 opacity-50" />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  )
}

function SelectValue({ className, ...props }: React.ComponentProps<typeof SelectPrimitive.Value>) {
  return <SelectPrimitive.Value className={cn("truncate", className)} {...props} />
}

function SelectContent({
  className,
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Popup>) {
  // Base UI Select requires Select.List around items — the popup looks up
  // a `listElement` from the store to wire keyboard navigation and item
  // selection. Without it, the popup never opens (or opens and immediately
  // closes because no items are registered). Symptom in production:
  // "cannot select project, cannot select scan type".
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Positioner sideOffset={4}>
        <SelectPrimitive.Popup
          className={cn(
            "z-50 min-w-[var(--anchor-width)] overflow-hidden rounded-lg border border-border bg-surface-2 p-1 text-popover-foreground shadow-xl data-[ending-style]:opacity-0 data-[starting-style]:opacity-0 transition-opacity",
            className
          )}
          {...props}
        >
          <SelectPrimitive.List>{children}</SelectPrimitive.List>
        </SelectPrimitive.Popup>
      </SelectPrimitive.Positioner>
    </SelectPrimitive.Portal>
  )
}

function SelectItem({
  className,
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Item>) {
  return (
    <SelectPrimitive.Item
      className={cn(
        "relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
        className
      )}
      {...props}
    >
      <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
        <SelectPrimitive.ItemIndicator>
          <Check className="h-4 w-4" />
        </SelectPrimitive.ItemIndicator>
      </span>
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
    </SelectPrimitive.Item>
  )
}

export {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
}
