"use client";

import { useState } from "react";
import { PageHeader } from "@/components/data/page-header";
import { ErrorState } from "@/components/data/error-state";
import { Pagination } from "@/components/data/pagination";
import { ScansTable } from "@/features/scans/scans-table";
import { useScans } from "@/features/scans/hooks";

const PAGE_SIZE = 25;

export default function ScansPage() {
  const [offset, setOffset] = useState(0);

  const { data, isLoading, isError, refetch } = useScans({ limit: PAGE_SIZE, offset });

  const scans = data?.scans ?? [];
  const hasMore = scans.length === PAGE_SIZE;

  return (
    <div>
      <PageHeader
        title="Scans"
        description="View and monitor security scan progress"
      />

      {isError ? (
        <ErrorState message="Failed to load scans" onRetry={() => refetch()} />
      ) : (
        <>
          <ScansTable scans={scans} isLoading={isLoading} />
          {!isLoading && scans.length > 0 && (
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
    </div>
  );
}
