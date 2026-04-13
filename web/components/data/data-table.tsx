"use client";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { LoadingState } from "./loading-state";
import { EmptyState } from "./empty-state";

export interface Column<T> {
  key: string;
  header: string;
  render: (item: T) => React.ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  isLoading?: boolean;
  /** Simple string fallback — rendered inside the default EmptyState. */
  emptyMessage?: string;
  /** Rich empty content — when provided, overrides `emptyMessage` and
   *  lets the consumer render a fully custom empty state (icon,
   *  description, CTA, etc). Use for feature-specific canonical empty
   *  states like `<RisksEmptyState>`. */
  emptyContent?: React.ReactNode;
  onRowClick?: (item: T) => void;
}

export function DataTable<T>({ columns, data, isLoading, emptyMessage = "No data found", emptyContent, onRowClick }: DataTableProps<T>) {
  if (isLoading) return <LoadingState rows={8} />;
  if (data.length === 0) return emptyContent ? <>{emptyContent}</> : <EmptyState title={emptyMessage} />;

  return (
    <Table>
      <TableHeader>
        <TableRow>
          {columns.map((col) => (
            <TableHead key={col.key} className={col.className}>{col.header}</TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((item, idx) => (
          <TableRow
            key={idx}
            className={onRowClick ? "cursor-pointer hover:bg-muted/50" : ""}
            onClick={() => onRowClick?.(item)}
          >
            {columns.map((col) => (
              <TableCell key={col.key} className={col.className}>{col.render(item)}</TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
