"use client";

import { PageHeader } from "@/components/data/page-header";
import { ErrorState } from "@/components/data/error-state";
import { SurfaceExplorer } from "@/features/surface/surface-explorer";
import { useSurface } from "@/features/surface/hooks";

export default function SurfacePage() {
  const { data, isLoading, isError, refetch } = useSurface();

  const entries = data?.entries ?? [];

  return (
    <div>
      <PageHeader
        title="Attack Surface"
        description="Discovered routes, forms, and endpoints across your applications"
      />

      {isError ? (
        <ErrorState message="Failed to load surface data" onRetry={() => refetch()} />
      ) : (
        <SurfaceExplorer entries={entries} isLoading={isLoading} />
      )}
    </div>
  );
}
