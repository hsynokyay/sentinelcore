import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getScans,
  getScan,
  createScan,
  cancelScan,
  getProjects,
  getScanTargets,
  type ScanFilters,
  type CreateScanPayload,
} from "./api";

export function useScans(filters: ScanFilters = {}) {
  return useQuery({
    queryKey: ["scans", filters],
    queryFn: () => getScans(filters),
  });
}

export function useScan(id: string) {
  const query = useQuery({
    queryKey: ["scans", id],
    queryFn: () => getScan(id),
    enabled: !!id,
    refetchInterval: (query) => {
      const scan = query.state.data?.scan;
      // Poll every 5s while scan is running
      if (scan && (scan.status === "running" || scan.status === "queued")) {
        return 5000;
      }
      return false;
    },
  });
  return query;
}

export function useProjects() {
  return useQuery({
    queryKey: ["projects"],
    queryFn: () => getProjects(),
  });
}

export function useScanTargets(projectId: string) {
  return useQuery({
    queryKey: ["scan-targets", projectId],
    queryFn: () => getScanTargets(projectId),
    enabled: !!projectId,
  });
}

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, data }: { projectId: string; data: CreateScanPayload }) =>
      createScan(projectId, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => cancelScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}
