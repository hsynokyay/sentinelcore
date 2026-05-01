import { cn } from "@/lib/utils"

export function LoadingState({
  rows = 8,
  columns = 5,
  className,
}: {
  rows?: number
  columns?: number
  className?: string
}) {
  return (
    <div className={cn("w-full overflow-hidden rounded-md border border-border-subtle", className)}>
      <div className="border-b border-border-subtle bg-surface-1 px-3 py-2.5 flex gap-3">
        {Array.from({ length: columns }).map((_, i) => (
          <div
            key={i}
            className="h-3 flex-1 shimmer rounded bg-surface-3"
            style={{ maxWidth: i === 0 ? 80 : i === columns - 1 ? 100 : undefined }}
          />
        ))}
      </div>
      <div className="divide-y divide-border-subtle">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="px-3 py-3 flex gap-3">
            {Array.from({ length: columns }).map((_, c) => (
              <div
                key={c}
                className="h-3 flex-1 shimmer rounded bg-surface-2"
                style={{
                  animationDelay: `${(r + c) * 30}ms`,
                  maxWidth: c === 0 ? 80 : c === columns - 1 ? 100 : undefined,
                }}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}
