"use client";

import { use } from "react";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { Button } from "@/components/ui/button";
import { RiskDetail } from "@/features/risks/risk-detail";
import { useRisk } from "@/features/risks/hooks";

export default function RiskDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { data, isLoading, isError, refetch } = useRisk(id);

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
      {data?.risk && <RiskDetail risk={data.risk} />}
    </div>
  );
}
