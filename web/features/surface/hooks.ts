import { useQuery } from "@tanstack/react-query";
import { getSurfaceEntries, getSurfaceStats, type SurfaceFilters } from "./api";

export function useSurface(filters: SurfaceFilters = {}) {
  return useQuery({
    queryKey: ["surface", filters],
    queryFn: () => getSurfaceEntries(filters),
  });
}

export function useSurfaceStats(projectId?: string) {
  return useQuery({
    queryKey: ["surface-stats", projectId],
    queryFn: () => getSurfaceStats(projectId),
  });
}
