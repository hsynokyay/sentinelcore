"use client"

import * as React from "react"
import { ChevronDown, ChevronUp } from "lucide-react"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table"
import { LoadingState } from "./loading-state"
import { EmptyState } from "./empty-state"
import { useDensity } from "@/lib/density-context"
import { cn } from "@/lib/utils"

export interface Column<T> {
  key: string
  header: string
  render: (item: T) => React.ReactNode
  className?: string
  /** When set, the column header becomes a sort toggle. */
  sortKey?: string
}

export interface SortState {
  key: string
  dir: "asc" | "desc"
}

interface DataTableProps<T> {
  columns: Column<T>[]
  data: T[]
  isLoading?: boolean
  emptyMessage?: string
  emptyContent?: React.ReactNode
  onRowClick?: (item: T) => void
  sort?: SortState
  onSortChange?: (sort: SortState) => void
}

export function DataTable<T>({
  columns,
  data,
  isLoading,
  emptyMessage = "No data found",
  emptyContent,
  onRowClick,
  sort,
  onSortChange,
}: DataTableProps<T>) {
  const { density } = useDensity()

  if (isLoading) return <LoadingState rows={8} columns={columns.length} />
  if (data.length === 0) return emptyContent ? <>{emptyContent}</> : <EmptyState title={emptyMessage} />

  return (
    <Table>
      <TableHeader>
        <TableRow>
          {columns.map((col) => {
            const isSorted = sort && sort.key === col.sortKey
            const sortable = !!col.sortKey && !!onSortChange
            return (
              <TableHead key={col.key} className={col.className}>
                {sortable ? (
                  <button
                    type="button"
                    onClick={() => {
                      if (!col.sortKey) return
                      onSortChange?.({
                        key: col.sortKey,
                        dir: isSorted && sort?.dir === "asc" ? "desc" : "asc",
                      })
                    }}
                    className="inline-flex items-center gap-1 hover:text-foreground transition-colors duration-fast"
                  >
                    {col.header}
                    {isSorted && sort?.dir === "asc" && <ChevronUp className="size-3" />}
                    {isSorted && sort?.dir === "desc" && <ChevronDown className="size-3" />}
                  </button>
                ) : (
                  col.header
                )}
              </TableHead>
            )
          })}
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((item, idx) => (
          <TableRow
            key={idx}
            data-density={density}
            className={cn(
              // The brand left-border accent uses an inset box-shadow (not a
              // ::before pseudo on the <tr>). HTML tables treat <tr> oddly
              // for positioning — `position: relative` + `::before { absolute }`
              // can be re-flowed into the row as an anonymous TABLE-CELL by
              // some browsers, shifting every other cell one column to the
              // right on hover. Inset shadow stays purely visual and never
              // affects layout.
              onRowClick &&
                "cursor-pointer hover:shadow-[inset_2px_0_0_0_var(--brand)]"
            )}
            onClick={() => onRowClick?.(item)}
          >
            {columns.map((col) => (
              <TableCell key={col.key} data-density={density} className={col.className}>
                {col.render(item)}
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
