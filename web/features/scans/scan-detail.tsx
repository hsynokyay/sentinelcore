"use client";

import Link from "next/link";
import { AlertCircle, KeyRound, FileArchive, Target as TargetIcon } from "lucide-react";
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

// Scans that sit in pending/queued for longer than this get an explicit
// "awaiting worker" hint in the UI. This is the honest UX for environments
// where a scan-type's worker isn't running — we never fake progress.
const AWAITING_WORKER_THRESHOLD_MS = 30_000;

function isAwaitingWorker(scan: Scan): boolean {
  if (scan.status !== "pending" && scan.status !== "queued") return false;
  const age = Date.now() - new Date(scan.created_at).getTime();
  return age > AWAITING_WORKER_THRESHOLD_MS;
}

interface ScanDetailProps {
  scan: Scan;
}

export function ScanDetail({ scan }: ScanDetailProps) {
  const awaitingWorker = isAwaitingWorker(scan);

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
          {scan.scan_profile && (
            <Badge variant="outline" className="text-xs">
              {scan.scan_profile}
            </Badge>
          )}
          {scan.trigger_type && scan.trigger_type !== "manual" && (
            <Badge variant="outline" className="text-xs">
              {scan.trigger_type}
            </Badge>
          )}
        </div>
      </div>

      {/* Awaiting worker banner */}
      {awaitingWorker && (
        <div className="flex items-start gap-3 rounded-md border border-amber-200 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-900 p-3">
          <AlertCircle className="h-4 w-4 text-amber-600 mt-0.5" />
          <div className="text-sm">
            <div className="font-medium text-amber-900 dark:text-amber-200">
              Waiting for scan worker
            </div>
            <p className="text-amber-800 dark:text-amber-300/90 mt-0.5">
              This scan is queued but has not been picked up yet. A{" "}
              {scan.scan_type.toUpperCase()} worker must be running to process
              it. Progress and findings will appear here once the worker
              consumes the job.
            </p>
          </div>
        </div>
      )}

      {/* Context — project, target, artifact, auth profile */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">
          Context
        </h3>
        <div className="rounded-md border divide-y">
          {scan.project_name && (
            <ContextRow label="Project" value={scan.project_name} />
          )}

          {scan.target_id && (
            <ContextRow
              label="Target"
              icon={<TargetIcon className="h-3.5 w-3.5" />}
              value={scan.target_label || scan.target_base_url || scan.target_id}
              subvalue={
                scan.target_base_url && scan.target_label
                  ? scan.target_base_url
                  : undefined
              }
            />
          )}

          {scan.source_artifact_id && (
            <ContextRow
              label="Source Artifact"
              icon={<FileArchive className="h-3.5 w-3.5" />}
              value={scan.source_artifact_name || scan.source_artifact_id}
            />
          )}

          {scan.auth_profile_id && (
            <ContextRow
              label="Auth Profile"
              icon={<KeyRound className="h-3.5 w-3.5" />}
              value={scan.auth_profile_name || scan.auth_profile_id}
              subvalue={scan.auth_profile_type?.replace("_", " ")}
            />
          )}

          {!scan.target_id && !scan.source_artifact_id && (
            <div className="px-4 py-3 text-sm text-muted-foreground">
              No target or source artifact recorded.
            </div>
          )}
        </div>
      </section>

      {/* Progress */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">
          Progress
        </h3>
        <div className="flex items-center gap-3">
          <div className="flex-1 max-w-md h-3 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-primary rounded-full transition-all"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <span className="text-sm font-medium">{scan.progress}%</span>
          {scan.progress_phase && scan.progress_phase !== "pending" && (
            <span className="text-xs text-muted-foreground">
              {scan.progress_phase}
            </span>
          )}
        </div>
      </section>

      {/* Timing */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Timing</h3>
        <div className="grid grid-cols-2 gap-4 max-w-md">
          <div>
            <span className="text-xs text-muted-foreground block">Created</span>
            <span className="text-sm">
              {new Date(scan.created_at).toLocaleString()}
            </span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Started</span>
            <span className="text-sm">
              {scan.started_at
                ? new Date(scan.started_at).toLocaleString()
                : "—"}
            </span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Finished</span>
            <span className="text-sm">
              {scan.finished_at
                ? new Date(scan.finished_at).toLocaleString()
                : "—"}
            </span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Duration</span>
            <span className="text-sm">
              {formatDuration(scan.started_at, scan.finished_at)}
            </span>
          </div>
        </div>
      </section>

      {/* Error (if any) */}
      {scan.error_message && (
        <section>
          <h3 className="text-sm font-medium text-muted-foreground mb-2">
            Error
          </h3>
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive">
            {scan.error_message}
          </div>
        </section>
      )}

      {/* Findings link */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">
          Findings
        </h3>
        <Link
          href={`/findings?scan_id=${scan.id}`}
          className="text-sm text-primary underline-offset-4 hover:underline"
        >
          View findings for this scan →
        </Link>
      </section>
    </div>
  );
}

interface ContextRowProps {
  label: string;
  value: string;
  subvalue?: string;
  icon?: React.ReactNode;
}

function ContextRow({ label, value, subvalue, icon }: ContextRowProps) {
  return (
    <div className="px-4 py-3 grid grid-cols-[160px_1fr] gap-3 items-start">
      <div className="text-xs text-muted-foreground flex items-center gap-1.5">
        {icon}
        {label}
      </div>
      <div>
        <div className="text-sm font-medium">{value}</div>
        {subvalue && (
          <div className="text-xs text-muted-foreground mt-0.5">{subvalue}</div>
        )}
      </div>
    </div>
  );
}
