"use client";

import { use } from "react";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { Button } from "@/components/ui/button";
import { ScanDetail } from "@/features/scans/scan-detail";
import { useScan } from "@/features/scans/hooks";

export default function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { data, isLoading, isError, refetch } = useScan(id);

  return (
    <div>
      <PageHeader
        title="Scan Detail"
        actions={
          <Link href="/scans">
            <Button variant="outline" size="sm">
              <ChevronLeft className="h-4 w-4 mr-1" /> Back to Scans
            </Button>
          </Link>
        }
      />

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load scan" onRetry={() => refetch()} />}
      {data?.scan && <ScanDetail scan={data.scan} />}
    </div>
  );
}
