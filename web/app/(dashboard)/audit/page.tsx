"use client";

import { FileText } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
import { AuditTable } from "@/features/audit/audit-table";
import { useAuditData } from "@/features/audit/hooks";

export default function AuditPage() {
  const { data, isLoading, isError, refetch } = useAuditData();

  return (
    <>
      <PageHeader
        title="Audit & Compliance"
        description="Compliance metrics, SLA tracking, and triage statistics"
      />

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load audit data" onRetry={() => refetch()} />}
      {!isLoading && !isError && !data && (
        <EmptyStateBranded
          icon={FileText}
          title="No audit events recorded"
          description="Audit events are generated as scans complete and findings are triaged."
        />
      )}
      {data && <AuditTable data={data} />}
    </>
  );
}
