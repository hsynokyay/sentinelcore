"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  invalid?: boolean
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, invalid, ...props }, ref) => {
    return (
      <input
        type={type}
        ref={ref}
        aria-invalid={invalid || undefined}
        className={cn(
          "h-9 w-full min-w-0 rounded-md border border-border bg-bg px-3 text-body transition-colors duration-fast outline-none focus-ring placeholder:text-muted-foreground disabled:pointer-events-none disabled:opacity-50",
          "aria-[invalid=true]:border-[color:var(--severity-critical)] aria-[invalid=true]:focus-visible:shadow-[0_0_0_2px_var(--bg),0_0_0_4px_var(--severity-critical)]",
          className
        )}
        {...props}
      />
    )
  }
)
Input.displayName = "Input"

export { Input }
