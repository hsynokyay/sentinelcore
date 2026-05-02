"use client";

import { useState } from "react";
import { Shield } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { DensityToggle } from "@/components/data/density-toggle";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
import { ErrorState } from "@/components/data/error-state";
import { Pagination } from "@/components/data/pagination";
import { FindingsTable } from "@/features/findings/findings-table";
import { FindingFiltersBar } from "@/features/findings/finding-filters";
import { useFindings } from "@/features/findings/hooks";

const PAGE_SIZE = 25;

export default function FindingsPage() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [findingType, setFindingType] = useState("");
  const [offset, setOffset] = useState(0);

  const filters = {
    severity: severity || undefined,
    status: status || undefined,
    finding_type: findingType || undefined,
    limit: PAGE_SIZE,
    offset,
  };

  const { data, isLoading, isError, refetch } = useFindings(filters);

  const findings = data?.findings ?? [];
  const hasMore = findings.length === PAGE_SIZE;
  const isEmpty = !isLoading && findings.length === 0;

  return (
    <>
      <PageHeader
        title="Findings"
        count={isLoading ? "—" : findings.length}
        filters={
          <FindingFiltersBar
            severity={severity}
            status={status}
            findingType={findingType}
            onSeverityChange={(v) => { setSeverity(v); setOffset(0); }}
            onStatusChange={(v) => { setStatus(v); setOffset(0); }}
            onTypeChange={(v) => { setFindingType(v); setOffset(0); }}
          />
        }
        actions={<DensityToggle />}
      />

      {isError ? (
        <ErrorState message="Failed to load findings" onRetry={() => refetch()} />
      ) : isEmpty ? (
        <EmptyStateBranded
          icon={Shield}
          title="No findings yet"
          description="Findings appear after a scan completes. Configure a target and run your first scan."
          action={{ label: "Go to scans", href: "/scans" }}
        />
      ) : (
        <>
          <FindingsTable findings={findings} isLoading={isLoading} />
          {!isLoading && findings.length > 0 && (
            <Pagination
              offset={offset}
              limit={PAGE_SIZE}
              hasMore={hasMore}
              onPrevious={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              onNext={() => setOffset(offset + PAGE_SIZE)}
            />
          )}
        </>
      )}
    </>
  );
}
