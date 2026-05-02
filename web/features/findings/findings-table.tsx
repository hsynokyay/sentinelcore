"use client";

import { useRouter } from "next/navigation";
import { DataTable, type Column } from "@/components/data/data-table";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { StatusBadge } from "@/components/badges/status-badge";
import { Badge } from "@/components/ui/badge";
import type { Finding } from "@/lib/types";

function formatRelativeDate(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

function truncate(str: string, max: number): string {
  return str.length > max ? str.slice(0, max) + "..." : str;
}

const typeColors: Record<string, string> = {
  sast: "bg-violet-100 text-violet-800",
  dast: "bg-cyan-100 text-cyan-800",
  sca: "bg-amber-100 text-amber-800",
};

const columns: Column<Finding>[] = [
  {
    key: "severity",
    header: "Severity",
    className: "w-[100px]",
    render: (f) => <SeverityBadge severity={f.severity} />,
  },
  {
    key: "title",
    header: "Title",
    render: (f) => (
      <span className="font-medium text-foreground">{truncate(f.title, 60)}</span>
    ),
  },
  {
    key: "type",
    header: "Type",
    className: "w-[80px]",
    render: (f) => (
      <Badge
        variant="outline"
        className={`text-xs uppercase ${typeColors[f.finding_type] || "bg-gray-100 text-gray-700"}`}
      >
        {f.finding_type}
      </Badge>
    ),
  },
  {
    key: "status",
    header: "Status",
    className: "w-[120px]",
    render: (f) => <StatusBadge status={f.status} />,
  },
  {
    key: "location",
    header: "Location",
    render: (f) => (
      <span className="text-sm text-muted-foreground font-mono">
        {f.file_path
          ? `${f.file_path}${f.line_number ? `:${f.line_number}` : ""}`
          : f.url || "-"}
      </span>
    ),
  },
  {
    key: "date",
    header: "Date",
    className: "w-[100px]",
    render: (f) => (
      <span className="text-sm text-muted-foreground">{formatRelativeDate(f.created_at)}</span>
    ),
  },
];

interface FindingsTableProps {
  findings: Finding[];
  isLoading?: boolean;
}

export function FindingsTable({ findings, isLoading }: FindingsTableProps) {
  const router = useRouter();

  return (
    <DataTable
      columns={columns}
      data={findings}
      isLoading={isLoading}
      emptyMessage="No findings found"
      onRowClick={(f) => router.push(`/findings/${f.id}`)}
    />
  );
}
