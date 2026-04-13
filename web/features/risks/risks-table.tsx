"use client";

import { useRouter } from "next/navigation";
import { DataTable, type Column } from "@/components/data/data-table";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { Badge } from "@/components/ui/badge";
import { ScoreDisplay } from "@/components/security/score-display";
import { SeverityStrip } from "@/components/security/severity-strip";
import type { RiskCluster, RiskStatus } from "@/lib/types";

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

const exposureColors: Record<string, string> = {
  public: "bg-red-100 text-red-800",
  authenticated: "bg-amber-100 text-amber-800",
  both: "bg-orange-100 text-orange-800",
  unknown: "bg-gray-100 text-gray-600",
};

/**
 * Map a risk lifecycle status to the visual state shared by every
 * security primitive (ScoreDisplay, SeverityStrip).
 *
 * - `active` and `auto_resolved` render as `active` because auto-resolved
 *   is transient (auto-reactivates the moment findings return), so the
 *   row should still feel live.
 * - `user_resolved` and `muted` are explicit user actions and earn the
 *   desaturated graphics treatment that visually steps the row back.
 *
 * Mirrors the helper in `risk-detail.tsx`. Kept local for now — if a
 * third consumer appears we'll promote it to `lib/security/`.
 */
function statusToLifecycleState(
  status: RiskStatus,
): "active" | "resolved" | "muted" {
  if (status === "user_resolved") return "resolved";
  if (status === "muted") return "muted";
  return "active";
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
    // The severity rail. The cell is `relative` so the absolutely-
    // positioned SeverityStrip uses it as its containing block — the
    // strip pins to top/bottom/left and naturally fills the row height
    // set by the other cells.
    key: "severity-rail",
    header: "",
    className: "w-[6px] p-0 relative",
    render: (r) => (
      <SeverityStrip
        severity={r.severity}
        state={statusToLifecycleState(r.status)}
      />
    ),
  },
  {
    key: "risk_score",
    header: "Score",
    className: "w-[140px]",
    render: (r) => (
      <ScoreDisplay
        score={r.risk_score}
        severity={r.severity}
        variant="sm"
        state={statusToLifecycleState(r.status)}
      />
    ),
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
  emptyContent,
}: {
  data: RiskCluster[];
  isLoading?: boolean;
  /** Rich empty content — wired up by the /risks page to show
   *  canonical empty states ("no risks yet" / "no matching risks"). */
  emptyContent?: React.ReactNode;
}) {
  const router = useRouter();
  return (
    <DataTable
      columns={columns}
      data={data}
      isLoading={isLoading}
      onRowClick={(row) => router.push(`/risks/${row.id}`)}
      emptyContent={emptyContent}
      emptyMessage="No risks yet. Risks appear after the first scan completes."
    />
  );
}
