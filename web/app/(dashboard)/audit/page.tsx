"use client";

import { PageHeader } from "@/components/data/page-header";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { AuditTable } from "@/features/audit/audit-table";
import { useAuditData } from "@/features/audit/hooks";

export default function AuditPage() {
  const { data, isLoading, isError, refetch } = useAuditData();

  return (
    <div>
      <PageHeader
        title="Audit & Compliance"
        description="Compliance metrics, SLA tracking, and triage statistics"
      />

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load audit data" onRetry={() => refetch()} />}
      {data && <AuditTable data={data} />}
    </div>
  );
}
