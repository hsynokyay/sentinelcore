"use client";

import { useState } from "react";
import { CheckCircle } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { DensityToggle } from "@/components/data/density-toggle";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
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
  const isEmpty = !isLoading && requests.length === 0;

  return (
    <>
      <PageHeader
        title="Approvals"
        description="Review and manage governance approval requests"
        count={isLoading ? "—" : (data?.total ?? requests.length)}
        actions={<DensityToggle />}
      />

      {isError ? (
        <ErrorState message="Failed to load approvals" onRetry={() => refetch()} />
      ) : isEmpty ? (
        <EmptyStateBranded
          icon={CheckCircle}
          title="No pending approvals"
          description="Approval requests appear when a governance policy requires sign-off before a finding is resolved."
        />
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
    </>
  );
}
