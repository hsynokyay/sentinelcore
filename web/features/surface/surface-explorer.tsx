"use client";

import { DataTable, type Column } from "@/components/data/data-table";
import { Badge } from "@/components/ui/badge";
import type { SurfaceEntry } from "@/lib/types";

const typeColors: Record<string, string> = {
  route: "bg-blue-100 text-blue-800",
  form: "bg-purple-100 text-purple-800",
  api_endpoint: "bg-emerald-100 text-emerald-800",
  clickable: "bg-orange-100 text-orange-800",
};

const exposureColors: Record<string, string> = {
  public: "bg-red-100 text-red-800",
  authenticated: "bg-green-100 text-green-800",
  both: "bg-yellow-100 text-yellow-800",
  unknown: "bg-gray-100 text-gray-600",
};

const columns: Column<SurfaceEntry>[] = [
  {
    key: "type",
    header: "Type",
    className: "w-[120px]",
    render: (e) => (
      <Badge
        variant="outline"
        className={`text-xs capitalize ${typeColors[e.type] || "bg-gray-100 text-gray-700"}`}
      >
        {e.type.replace(/_/g, " ")}
      </Badge>
    ),
  },
  {
    key: "url",
    header: "URL",
    render: (e) => (
      <span className="text-sm font-mono text-foreground">{e.url}</span>
    ),
  },
  {
    key: "method",
    header: "Method",
    className: "w-[80px]",
    render: (e) => (
      <span className="text-xs font-mono font-semibold text-muted-foreground">{e.method}</span>
    ),
  },
  {
    key: "exposure",
    header: "Exposure",
    className: "w-[120px]",
    render: (e) => (
      <Badge
        variant="outline"
        className={`text-xs capitalize ${exposureColors[e.exposure] || exposureColors.unknown}`}
      >
        {e.exposure}
      </Badge>
    ),
  },
  {
    key: "findings",
    header: "Findings",
    className: "w-[90px]",
    render: (e) => (
      <span className="text-sm text-muted-foreground">
        {e.finding_ids ? e.finding_ids.length : 0}
      </span>
    ),
  },
  {
    key: "scans",
    header: "Scans",
    className: "w-[80px]",
    render: (e) => (
      <span className="text-sm text-muted-foreground">{e.scan_count}</span>
    ),
  },
];

interface SurfaceExplorerProps {
  entries: SurfaceEntry[];
  isLoading?: boolean;
}

export function SurfaceExplorer({ entries, isLoading }: SurfaceExplorerProps) {
  return (
    <DataTable
      columns={columns}
      data={entries}
      isLoading={isLoading}
      emptyMessage="No surface entries discovered yet"
    />
  );
}
