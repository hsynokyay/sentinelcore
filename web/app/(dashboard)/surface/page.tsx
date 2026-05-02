"use client";

import { Globe } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { DensityToggle } from "@/components/data/density-toggle";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
import { ErrorState } from "@/components/data/error-state";
import { SurfaceExplorer } from "@/features/surface/surface-explorer";
import { useSurface } from "@/features/surface/hooks";

export default function SurfacePage() {
  const { data, isLoading, isError, refetch } = useSurface();

  const entries = data?.entries ?? [];
  const isEmpty = !isLoading && entries.length === 0;

  return (
    <>
      <PageHeader
        title="Attack Surface"
        description="Discovered routes, forms, and endpoints across your applications"
        count={isLoading ? "—" : entries.length}
        actions={<DensityToggle />}
      />

      {isError ? (
        <ErrorState message="Failed to load surface data" onRetry={() => refetch()} />
      ) : isEmpty ? (
        <EmptyStateBranded
          icon={Globe}
          title="No surface entries yet"
          description="Attack surface entries are discovered automatically during DAST scans."
        />
      ) : (
        <SurfaceExplorer entries={entries} isLoading={isLoading} />
      )}
    </>
  );
}
