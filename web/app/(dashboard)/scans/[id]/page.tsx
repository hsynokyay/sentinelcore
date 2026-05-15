"use client";

import { use } from "react";
import Link from "next/link";
import { ChevronLeft, XCircle } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/data/page-header";
import { DetailShell } from "@/components/data/detail-shell";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/badges/status-badge";
import { ScanDetail } from "@/features/scans/scan-detail";
import { useScan, useCancelScan } from "@/features/scans/hooks";
import { ExportScanReportButton } from "@/features/export/export-scan-report-button";
import { ExportScanSarifButton } from "@/features/export/export-sarif-buttons";

function formatDate(s: string | null | undefined): string {
  if (!s) return "—";
  return new Date(s).toLocaleDateString();
}

function formatDuration(start?: string, end?: string): string {
  if (!start) return "—";
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const diffSec = Math.floor((e - s) / 1000);
  if (diffSec < 60) return `${diffSec}s`;
  return `${Math.floor(diffSec / 60)}m ${diffSec % 60}s`;
}

export default function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { data, isLoading, isError, refetch } = useScan(id);
  const cancelScan = useCancelScan();

  const scan = data?.scan;
  const isRunning = scan?.status === "running" || scan?.status === "pending" || scan?.status === "queued";

  const handleCancel = () => {
    if (!scan) return;
    cancelScan.mutate(scan.id, {
      onSuccess: () => toast.success("Scan cancelled"),
      onError: (err) =>
        toast.error("Failed to cancel scan", {
          description: err instanceof Error ? err.message : "Unknown error",
        }),
    });
  };

  return (
    <div>
      <PageHeader
        title="Scan Detail"
        actions={
          <Link href="/scans">
            <Button variant="outline" size="sm">
              <ChevronLeft className="h-4 w-4 mr-1" /> Back to Scans
            </Button>
          </Link>
        }
      />

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load scan" onRetry={() => refetch()} />}
      {scan && (
        <DetailShell
          leftRail={
            <dl className="space-y-2">
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Status</dt>
                <dd><StatusBadge status={scan.status} /></dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Type</dt>
                <dd className="text-xs uppercase font-medium">{scan.scan_type}</dd>
              </div>
              {scan.scan_profile && (
                <div className="flex items-center justify-between">
                  <dt className="text-muted-foreground">Profile</dt>
                  <dd className="text-xs">{scan.scan_profile}</dd>
                </div>
              )}
              {scan.target_base_url && (
                <div className="flex items-center justify-between">
                  <dt className="text-muted-foreground">Target</dt>
                  <dd className="font-mono text-xs truncate max-w-[120px]" title={scan.target_base_url}>{scan.target_base_url}</dd>
                </div>
              )}
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Started</dt>
                <dd>{formatDate(scan.started_at ?? scan.created_at)}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Duration</dt>
                <dd>{formatDuration(scan.started_at, scan.finished_at)}</dd>
              </div>
              {scan.progress > 0 && (
                <div className="flex items-center justify-between">
                  <dt className="text-muted-foreground">Progress</dt>
                  <dd>{scan.progress}%</dd>
                </div>
              )}
            </dl>
          }
          main={
            <>
              <div className="flex justify-end gap-1.5 mb-4">
                <ExportScanReportButton scan={scan} />
                <ExportScanSarifButton scan={scan} />
              </div>
              <ScanDetail scan={scan} />
            </>
          }
          rightRail={
            isRunning ? (
              <div className="flex flex-col gap-1.5">
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleCancel}
                  disabled={cancelScan.isPending}
                >
                  <XCircle className="h-4 w-4 mr-1" />
                  {cancelScan.isPending ? "Cancelling…" : "Cancel scan"}
                </Button>
              </div>
            ) : undefined
          }
        />
      )}
    </div>
  );
}
