"use client"

import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-body font-medium select-none transition-[transform,box-shadow,background-color,color,border-color] duration-fast ease-[cubic-bezier(0.16,1,0.3,1)] focus-ring disabled:pointer-events-none disabled:opacity-50 active:translate-y-[0.5px] [&>svg]:size-4 [&>svg]:shrink-0",
  {
    variants: {
      variant: {
        primary:
          "bg-brand text-brand-foreground hover:bg-brand/90 hover:-translate-y-[0.5px] hover:shadow-[0_2px_8px_-2px_rgba(0,0,0,0.25)]",
        secondary:
          "bg-surface-2 text-foreground border border-border hover:bg-surface-3 hover:-translate-y-[0.5px]",
        ghost:
          "text-foreground hover:bg-surface-2",
        outline:
          "bg-transparent text-foreground border border-border hover:bg-surface-2 hover:border-border-strong",
        destructive:
          "bg-[color:var(--severity-critical)] text-white hover:opacity-90 hover:-translate-y-[0.5px]",
      },
      size: {
        xs: "h-7 px-2 text-body-sm",
        sm: "h-8 px-2.5 text-body-sm",
        md: "h-9 px-3",
        lg: "h-10 px-4",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  }
)

interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
Button.displayName = "Button"

export { Button, buttonVariants }
