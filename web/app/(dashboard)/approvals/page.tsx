"use client";

import { useState } from "react";
import { PageHeader } from "@/components/data/page-header";
import { ErrorState } from "@/components/data/error-state";
import { Pagination } from "@/components/data/pagination";
import { ApprovalsTable } from "@/features/governance/approvals-table";
import { useApprovals } from "@/features/governance/hooks";

const PAGE_SIZE = 25;

export default function ApprovalsPage() {
  const [offset, setOffset] = useState(0);

  const { data, isLoading, isError, refetch } = useApprovals({ limit: PAGE_SIZE, offset });

  const requests = data?.approvals ?? [];
  const hasMore = requests.length === PAGE_SIZE;

  return (
    <div>
      <PageHeader
        title="Approvals"
        description="Review and manage governance approval requests"
      />

      {isError ? (
        <ErrorState message="Failed to load approvals" onRetry={() => refetch()} />
      ) : (
        <>
          <ApprovalsTable requests={requests} isLoading={isLoading} />
          {!isLoading && requests.length > 0 && (
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
