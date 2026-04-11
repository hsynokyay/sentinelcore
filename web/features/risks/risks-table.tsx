"use client";

import { useRouter } from "next/navigation";
import { DataTable, type Column } from "@/components/data/data-table";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { Badge } from "@/components/ui/badge";
import type { RiskCluster } from "@/lib/types";

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

const scoreBarColor: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-slate-400",
};

const exposureColors: Record<string, string> = {
  public: "bg-red-100 text-red-800",
  authenticated: "bg-amber-100 text-amber-800",
  both: "bg-orange-100 text-orange-800",
  unknown: "bg-gray-100 text-gray-600",
};

function ScoreBar({ score, severity }: { score: number; severity: string }) {
  const color = scoreBarColor[severity] ?? "bg-slate-400";
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-20 rounded bg-muted overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${Math.min(100, score)}%` }} />
      </div>
      <span className="text-sm font-semibold tabular-nums w-8 text-right">{score}</span>
    </div>
  );
}

function ReasonsSummary({ risk }: { risk: RiskCluster }) {
  if (!risk.top_reasons || risk.top_reasons.length === 0) return null;
  const parts = risk.top_reasons.map((r) => {
    if (r.weight != null) return `${r.label} (${r.weight >= 0 ? "+" : ""}${r.weight})`;
    return r.label;
  });
  return (
    <span className="text-xs text-muted-foreground truncate">{parts.join(" · ")}</span>
  );
}

const columns: Column<RiskCluster>[] = [
  {
    key: "risk_score",
    header: "Score",
    className: "w-[160px]",
    render: (r) => <ScoreBar score={r.risk_score} severity={r.severity} />,
  },
  {
    key: "severity",
    header: "Severity",
    className: "w-[100px]",
    render: (r) => <SeverityBadge severity={r.severity} />,
  },
  {
    key: "title",
    header: "Title",
    render: (r) => (
      <div className="min-w-0">
        <div className="font-medium text-foreground truncate">{r.title}</div>
        <ReasonsSummary risk={r} />
      </div>
    ),
  },
  {
    key: "vuln_class",
    header: "Class",
    className: "w-[160px]",
    render: (r) => (
      <Badge variant="outline" className="text-xs">
        {r.vuln_class.replace(/_/g, " ")}
      </Badge>
    ),
  },
  {
    key: "exposure",
    header: "Exposure",
    className: "w-[120px]",
    render: (r) => (
      <Badge className={`text-xs uppercase ${exposureColors[r.exposure] ?? exposureColors.unknown}`}>
        {r.exposure}
      </Badge>
    ),
  },
  {
    key: "findings",
    header: "Findings",
    className: "w-[90px] text-center",
    render: (r) => <span className="text-sm tabular-nums">{r.finding_count}</span>,
  },
  {
    key: "last_seen",
    header: "Last seen",
    className: "w-[110px]",
    render: (r) => (
      <span className="text-xs text-muted-foreground">{formatRelativeDate(r.last_seen_at)}</span>
    ),
  },
];

export function RisksTable({
  data,
  isLoading,
}: {
  data: RiskCluster[];
  isLoading?: boolean;
}) {
  const router = useRouter();
  return (
    <DataTable
      columns={columns}
      data={data}
      isLoading={isLoading}
      onRowClick={(row) => router.push(`/risks/${row.id}`)}
      emptyMessage="No risks yet. Risks appear after the first scan completes."
    />
  );
}
