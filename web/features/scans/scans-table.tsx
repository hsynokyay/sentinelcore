"use client";

import { useRouter } from "next/navigation";
import { DataTable, type Column } from "@/components/data/data-table";
import { StatusBadge } from "@/components/badges/status-badge";
import { Badge } from "@/components/ui/badge";
import type { Scan } from "@/lib/types";

function formatDuration(start?: string, end?: string): string {
  if (!start) return "-";
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const diffSec = Math.floor((e - s) / 1000);
  if (diffSec < 60) return `${diffSec}s`;
  const mins = Math.floor(diffSec / 60);
  const secs = diffSec % 60;
  return `${mins}m ${secs}s`;
}

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

const scanTypeColors: Record<string, string> = {
  sast: "bg-violet-100 text-violet-800",
  dast: "bg-cyan-100 text-cyan-800",
  sca: "bg-amber-100 text-amber-800",
};

const columns: Column<Scan>[] = [
  {
    key: "scan_type",
    header: "Type",
    className: "w-[80px]",
    render: (s) => (
      <Badge
        variant="outline"
        className={`text-xs uppercase ${scanTypeColors[s.scan_type] || "bg-gray-100 text-gray-700"}`}
      >
        {s.scan_type}
      </Badge>
    ),
  },
  {
    key: "status",
    header: "Status",
    className: "w-[120px]",
    render: (s) => <StatusBadge status={s.status} />,
  },
  {
    key: "input",
    header: "Input",
    render: (s) => {
      if (s.source_artifact_id) {
        return (
          <span className="text-sm">
            <span className="text-muted-foreground">artifact:</span>{" "}
            {s.source_artifact_name || s.source_artifact_id.slice(0, 8)}
          </span>
        );
      }
      if (s.target_id) {
        return (
          <span className="text-sm">
            {s.target_label || s.target_base_url || (
              <span className="font-mono text-muted-foreground">
                {s.target_id.slice(0, 8)}
              </span>
            )}
          </span>
        );
      }
      return <span className="text-xs text-muted-foreground">—</span>;
    },
  },
  {
    key: "progress",
    header: "Progress",
    className: "w-[120px]",
    render: (s) => (
      <div className="flex items-center gap-2">
        <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
          <div
            className="h-full bg-primary rounded-full transition-all"
            style={{ width: `${s.progress}%` }}
          />
        </div>
        <span className="text-xs text-muted-foreground w-8 text-right">{s.progress}%</span>
      </div>
    ),
  },
  {
    key: "duration",
    header: "Duration",
    className: "w-[100px]",
    render: (s) => (
      <span className="text-sm text-muted-foreground">
        {formatDuration(s.started_at, s.finished_at)}
      </span>
    ),
  },
  {
    key: "date",
    header: "Created",
    className: "w-[100px]",
    render: (s) => (
      <span className="text-sm text-muted-foreground">{formatRelativeDate(s.created_at)}</span>
    ),
  },
];

interface ScansTableProps {
  scans: Scan[];
  isLoading?: boolean;
}

export function ScansTable({ scans, isLoading }: ScansTableProps) {
  const router = useRouter();

  return (
    <DataTable
      columns={columns}
      data={scans}
      isLoading={isLoading}
      emptyMessage="No scans found"
      onRowClick={(s) => router.push(`/scans/${s.id}`)}
    />
  );
}
