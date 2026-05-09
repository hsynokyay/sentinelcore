"use client";

import { useState } from "react";
import { CheckCircle } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { DensityToggle } from "@/components/data/density-toggle";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
import { ErrorState } from "@/components/data/error-state";
import { Pagination } from "@/components/data/pagination";
import { ApprovalsTable } from "@/features/governance/approvals-table";
import { ApprovalsInbox } from "@/features/governance/approvals-inbox";
import { useApprovals } from "@/features/governance/hooks";

const PAGE_SIZE = 25;

type Tab = "inbox" | "all";

export default function ApprovalsPage() {
  const [tab, setTab] = useState<Tab>("inbox");
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
        count={isLoading ? "—" : requests.length}
        actions={<DensityToggle />}
      />

      {/* Phase-5 inbox + legacy table tab. The inbox surfaces pending
          two-person approvals via the new /decisions endpoint; the All
          tab keeps the previous list view for back-compat. */}
      <div className="mb-4 flex items-center gap-2 border-b">
        <button
          type="button"
          onClick={() => setTab("inbox")}
          className={`px-3 py-2 text-sm border-b-2 transition-colors ${
            tab === "inbox"
              ? "border-primary text-primary"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          Inbox (Pending)
        </button>
        <button
          type="button"
          onClick={() => setTab("all")}
          className={`px-3 py-2 text-sm border-b-2 transition-colors ${
            tab === "all"
              ? "border-primary text-primary"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          All Requests
        </button>
      </div>

      {tab === "inbox" ? (
        <ApprovalsInbox status="pending" />
      ) : isError ? (
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
