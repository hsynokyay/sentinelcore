"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

const Label = React.forwardRef<
  HTMLLabelElement,
  React.LabelHTMLAttributes<HTMLLabelElement>
>(({ className, ...props }, ref) => (
  <label
    ref={ref}
    className={cn(
      "block text-body-sm font-medium text-foreground select-none mb-1.5 group-data-[disabled=true]:opacity-50",
      className
    )}
    {...props}
  />
))
Label.displayName = "Label"

export { Label }
