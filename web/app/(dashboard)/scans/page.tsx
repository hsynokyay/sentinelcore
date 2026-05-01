"use client";

import { useState } from "react";
import { Plus, Play } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { DensityToggle } from "@/components/data/density-toggle";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
import { ErrorState } from "@/components/data/error-state";
import { Pagination } from "@/components/data/pagination";
import { Button } from "@/components/ui/button";
import { ScansTable } from "@/features/scans/scans-table";
import { useScans } from "@/features/scans/hooks";
import { CreateScanDialog } from "@/features/scans/create-scan-dialog";

const PAGE_SIZE = 25;

export default function ScansPage() {
  const [offset, setOffset] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);

  const { data, isLoading, isError, refetch } = useScans({ limit: PAGE_SIZE, offset });

  const scans = data?.scans ?? [];
  const hasMore = scans.length === PAGE_SIZE;
  const isEmpty = !isLoading && scans.length === 0;

  return (
    <>
      <PageHeader
        title="Scans"
        description="View and monitor security scan progress"
        count={isLoading ? "—" : scans.length}
        actions={
          <>
            <DensityToggle />
            <Button onClick={() => setDialogOpen(true)}>
              <Plus className="h-4 w-4 mr-1" />
              New Scan
            </Button>
          </>
        }
      />

      <CreateScanDialog open={dialogOpen} onOpenChange={setDialogOpen} />

      {isError ? (
        <ErrorState message="Failed to load scans" onRetry={() => refetch()} />
      ) : isEmpty ? (
        <EmptyStateBranded
          icon={Play}
          title="No scans yet"
          description="Configure a scan target to run your first scan."
          action={{ label: "Configure target", href: "/targets" }}
        />
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
    </>
  );
}
