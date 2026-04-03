"use client";

import Link from "next/link";
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

interface ScanDetailProps {
  scan: Scan;
}

export function ScanDetail({ scan }: ScanDetailProps) {
  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h2 className="text-xl font-semibold tracking-tight mb-3">
          Scan {scan.id.slice(0, 8)}
        </h2>
        <div className="flex items-center gap-2 flex-wrap">
          <StatusBadge status={scan.status} />
          <Badge variant="outline" className="text-xs uppercase">
            {scan.scan_type}
          </Badge>
        </div>
      </div>

      {/* Progress */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Progress</h3>
        <div className="flex items-center gap-3">
          <div className="flex-1 max-w-md h-3 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-primary rounded-full transition-all"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <span className="text-sm font-medium">{scan.progress}%</span>
        </div>
      </section>

      {/* Timing */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Timing</h3>
        <div className="grid grid-cols-2 gap-4 max-w-md">
          <div>
            <span className="text-xs text-muted-foreground block">Created</span>
            <span className="text-sm">{new Date(scan.created_at).toLocaleString()}</span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Started</span>
            <span className="text-sm">
              {scan.started_at ? new Date(scan.started_at).toLocaleString() : "-"}
            </span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Finished</span>
            <span className="text-sm">
              {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "-"}
            </span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Duration</span>
            <span className="text-sm">{formatDuration(scan.started_at, scan.finished_at)}</span>
          </div>
        </div>
      </section>

      {/* Target */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Target</h3>
        <code className="text-sm bg-muted px-2 py-1 rounded font-mono">{scan.target_id}</code>
      </section>

      {/* Findings Link */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Findings</h3>
        <Link
          href={`/findings?scan_id=${scan.id}`}
          className="text-sm text-primary underline-offset-4 hover:underline"
        >
          View findings for this scan
        </Link>
      </section>
    </div>
  );
}
