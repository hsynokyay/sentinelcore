"use client";

import { use } from "react";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { DetailShell } from "@/components/data/detail-shell";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { StatusBadge } from "@/components/badges/status-badge";
import { FindingDetail } from "@/features/findings/finding-detail";
import { useFinding } from "@/features/findings/hooks";

function formatDate(s: string | null | undefined): string {
  if (!s) return "—";
  return new Date(s).toLocaleDateString();
}

export default function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { data, isLoading, isError, refetch } = useFinding(id);

  const f = data?.finding;

  const location = f
    ? f.file_path
      ? `${f.file_path}${f.line_number ? `:${f.line_number}` : ""}`
      : f.url
        ? `${f.method || "GET"} ${f.url}`
        : "—"
    : "—";

  return (
    <div>
      <PageHeader
        title="Finding Detail"
        actions={
          <Link href="/findings">
            <Button variant="outline" size="sm">
              <ChevronLeft className="h-4 w-4 mr-1" /> Back to Findings
            </Button>
          </Link>
        }
      />

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load finding" onRetry={() => refetch()} />}
      {f && (
        <DetailShell
          leftRail={
            <dl className="space-y-2">
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Severity</dt>
                <dd><SeverityBadge severity={f.severity} /></dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Status</dt>
                <dd><StatusBadge status={f.status} /></dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Type</dt>
                <dd className="text-xs uppercase font-medium">{f.finding_type}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Scan</dt>
                <dd className="font-mono text-xs">#{f.scan_id?.slice(0, 8)}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Location</dt>
                <dd className="font-mono text-xs truncate max-w-[120px]" title={location}>{location}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Reported</dt>
                <dd>{formatDate(f.created_at)}</dd>
              </div>
            </dl>
          }
          main={<FindingDetail finding={f} />}
        />
      )}
    </div>
  );
}
