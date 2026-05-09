"use client";

// Phase-5 governance ops: SLA posture dashboard.
//
// Surfaces three counter cards (breached / at-risk / on-track), the
// top-25 most-overdue findings, and a 30-day breach-trend sparkline.
// Backed by GET /api/v1/governance/sla/dashboard.

import { useMemo } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/data/data-table";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";

import { useSLADashboard } from "./hooks";
import type { BreachSummary, TrendBucket } from "@/lib/types";

function formatHours(hours: number): string {
  if (hours < 1) return "<1h";
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  const rem = hours % 24;
  return rem === 0 ? `${days}d` : `${days}d ${rem}h`;
}

function severityClass(severity: string): string {
  switch (severity) {
    case "critical":
      return "text-red-600";
    case "high":
      return "text-orange-600";
    case "medium":
      return "text-yellow-600";
    case "low":
      return "text-blue-600";
    default:
      return "text-muted-foreground";
  }
}

interface SparklineProps {
  data: TrendBucket[];
  width?: number;
  height?: number;
}

function Sparkline({ data, width = 220, height = 40 }: SparklineProps) {
  if (data.length === 0) {
    return <span className="text-xs text-muted-foreground">No data in last 30 days</span>;
  }
  const max = Math.max(...data.map((b) => b.breaches), 1);
  const stepX = data.length > 1 ? width / (data.length - 1) : 0;
  const points = data
    .map((b, i) => {
      const x = i * stepX;
      const y = height - (b.breaches / max) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg width={width} height={height} role="img" aria-label="30-day breach trend">
      <polyline
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        points={points}
        className="text-red-500"
      />
    </svg>
  );
}

interface CounterCardProps {
  label: string;
  value: number;
  tone: "danger" | "warning" | "ok";
}

function CounterCard({ label, value, tone }: CounterCardProps) {
  const toneClass =
    tone === "danger"
      ? "text-red-600"
      : tone === "warning"
        ? "text-yellow-600"
        : "text-green-600";
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className={`text-3xl font-semibold tabular-nums ${toneClass}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

export function SLADashboard() {
  const { data, isLoading, isError, refetch } = useSLADashboard(7);

  const columns: Column<BreachSummary>[] = useMemo(
    () => [
      {
        key: "severity",
        header: "Severity",
        className: "w-[110px]",
        render: (b) => (
          <span className={`text-sm font-medium capitalize ${severityClass(b.severity)}`}>
            {b.severity}
          </span>
        ),
      },
      {
        key: "title",
        header: "Title",
        render: (b) => <span className="text-sm">{b.title}</span>,
      },
      {
        key: "overdue",
        header: "Overdue",
        className: "w-[120px]",
        render: (b) => (
          <span className="font-mono text-sm tabular-nums text-red-600">
            {formatHours(b.overdue_hours)}
          </span>
        ),
      },
      {
        key: "deadline",
        header: "Deadline",
        className: "w-[160px]",
        render: (b) => (
          <span className="text-xs text-muted-foreground">
            {new Date(b.deadline_at).toLocaleString()}
          </span>
        ),
      },
      {
        key: "finding",
        header: "Finding",
        className: "w-[120px]",
        render: (b) => (
          <span className="text-xs font-mono text-muted-foreground">
            {b.finding_id.slice(0, 8)}
          </span>
        ),
      },
    ],
    [],
  );

  if (isLoading) return <LoadingState rows={6} />;
  if (isError || !data)
    return <ErrorState message="Failed to load SLA dashboard" onRetry={() => refetch()} />;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <CounterCard label="Breached" value={data.counts_by_status.breached ?? 0} tone="danger" />
        <CounterCard label="At Risk" value={data.counts_by_status.at_risk ?? 0} tone="warning" />
        <CounterCard label="On Track" value={data.counts_by_status.on_track ?? 0} tone="ok" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">30-day breach trend</CardTitle>
        </CardHeader>
        <CardContent>
          <Sparkline data={data.trend} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Top breaches</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={data.top_breaches}
            emptyMessage="No SLA breaches"
          />
        </CardContent>
      </Card>
    </div>
  );
}
