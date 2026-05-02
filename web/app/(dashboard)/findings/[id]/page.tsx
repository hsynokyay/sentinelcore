"use client";

import { use } from "react";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { Button } from "@/components/ui/button";
import { FindingDetail } from "@/features/findings/finding-detail";
import { useFinding } from "@/features/findings/hooks";

export default function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { data, isLoading, isError, refetch } = useFinding(id);

  return (
    <div>
      <PageHeader
        title="Finding Detail"
        actions={
          <Link href="/findings">
            <Button variant="outline" size="sm">
              <ChevronLeft className="h-4 w-4 mr-1" /> Back to Findings
            </Button>
          </Link>
        }
      />

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load finding" onRetry={() => refetch()} />}
      {data?.finding && <FindingDetail finding={data.finding} />}
    </div>
  );
}
