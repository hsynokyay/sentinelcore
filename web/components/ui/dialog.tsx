"use client"

import * as React from "react"
import { Dialog as DialogPrimitive } from "@base-ui/react/dialog"
import { X } from "lucide-react"

import { cn } from "@/lib/utils"

function Dialog({
  open,
  onOpenChange,
  ...props
}: Omit<React.ComponentProps<typeof DialogPrimitive.Root>, "onOpenChange"> & {
  onOpenChange?: (open: boolean) => void;
}) {
  // `modal='trap-focus'` keeps focus inside the dialog (good UX) but does NOT
  // apply `inert` to outside elements or lock scroll. The default `modal=true`
  // mode applies inert via Base UI's markOthers utility; if that cleanup races
  // with React's concurrent unmount, inert leaks and the sidebar / main content
  // become unclickable. trap-focus avoids the whole class of leak.
  //
  // `disablePointerDismissal=true` is required because nested portal-based
  // popups (Select, Popover, etc. which themselves portal to body) sit
  // OUTSIDE the dialog tree. With trap-focus mode, clicks on those nested
  // popups are seen as outside-click and dismiss the dialog mid-interaction.
  // Form dialogs in this app always contain at least one Select; explicit
  // close (X button, Escape, Cancel button) remains available.
  return (
    <DialogPrimitive.Root
      open={open}
      modal="trap-focus"
      disablePointerDismissal
      onOpenChange={onOpenChange ? (value) => onOpenChange(value) : undefined}
      {...props}
    />
  )
}

const DialogTrigger = DialogPrimitive.Trigger

const DialogClose = DialogPrimitive.Close

function DialogPortal({ children }: { children: React.ReactNode }) {
  return <DialogPrimitive.Portal>{children}</DialogPrimitive.Portal>
}

function DialogBackdrop({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Backdrop>) {
  return (
    <DialogPrimitive.Backdrop
      className={cn(
        "fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[ending-style]:opacity-0 data-[starting-style]:opacity-0 transition-opacity duration-slow ease-[cubic-bezier(0.16,1,0.3,1)]",
        className
      )}
      {...props}
    />
  )
}

const sizeClass = {
  sm: "max-w-sm",
  md: "max-w-lg",
  lg: "max-w-3xl",
} as const

function DialogContent({
  className,
  children,
  size = "md",
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Popup> & {
  size?: keyof typeof sizeClass
}) {
  return (
    <DialogPortal>
      <DialogBackdrop />
      <DialogPrimitive.Popup
        className={cn(
          "fixed left-1/2 top-1/2 z-50 w-full -translate-x-1/2 -translate-y-1/2 rounded-xl border border-border bg-surface-2 p-6 shadow-2xl data-[ending-style]:opacity-0 data-[ending-style]:scale-95 data-[starting-style]:opacity-0 data-[starting-style]:scale-95 transition-all duration-slow ease-[cubic-bezier(0.16,1,0.3,1)]",
          sizeClass[size],
          className
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close
          className="absolute right-4 top-4 rounded-sm opacity-70 hover:opacity-100 transition-opacity focus-ring"
        >
          <X className="h-4 w-4" />
          <span className="sr-only">Close</span>
        </DialogPrimitive.Close>
      </DialogPrimitive.Popup>
    </DialogPortal>
  )
}

function DialogHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("flex flex-col gap-1.5 text-center sm:text-left mb-4", className)}
      {...props}
    />
  )
}

function DialogFooter({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("flex flex-col-reverse sm:flex-row sm:justify-end gap-2 mt-4", className)}
      {...props}
    />
  )
}

function DialogTitle({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Title>) {
  return (
    <DialogPrimitive.Title
      className={cn("text-lg font-semibold leading-none tracking-tight", className)}
      {...props}
    />
  )
}

function DialogDescription({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description
      className={cn("text-sm text-muted-foreground", className)}
      {...props}
    />
  )
}

export {
  Dialog,
  DialogTrigger,
  DialogClose,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
}
