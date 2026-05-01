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
              onRowClick &&
                "cursor-pointer relative hover:before:absolute hover:before:left-0 hover:before:top-0 hover:before:bottom-0 hover:before:w-[2px] hover:before:bg-brand"
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
