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
import { RiskDetail } from "@/features/risks/risk-detail";
import { useRisk } from "@/features/risks/hooks";

function formatDate(s: string | null | undefined): string {
  if (!s) return "—";
  return new Date(s).toLocaleDateString();
}

export default function RiskDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { data, isLoading, isError, refetch } = useRisk(id);

  const r = data?.risk;

  return (
    <div>
      <PageHeader
        title="Risk Detail"
        actions={
          <Link href="/risks">
            <Button variant="outline" size="sm">
              <ChevronLeft className="h-4 w-4 mr-1" /> Back to Risks
            </Button>
          </Link>
        }
      />

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load risk" onRetry={() => refetch()} />}
      {r && (
        <DetailShell
          leftRail={
            <dl className="space-y-2">
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Severity</dt>
                <dd><SeverityBadge severity={r.severity} /></dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Status</dt>
                <dd><StatusBadge status={r.status} /></dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Risk score</dt>
                <dd className="font-semibold">{r.risk_score}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Findings</dt>
                <dd>{r.finding_count}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">CWE</dt>
                <dd className="font-mono text-xs">CWE-{r.cwe_id}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">First seen</dt>
                <dd>{formatDate(r.first_seen_at)}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-muted-foreground">Last seen</dt>
                <dd>{formatDate(r.last_seen_at)}</dd>
              </div>
            </dl>
          }
          main={<RiskDetail risk={r} />}
        />
      )}
    </div>
  );
}
