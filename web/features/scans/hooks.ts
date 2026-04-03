import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getScans, getScan, createScan, cancelScan, type ScanFilters } from "./api";

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

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, data }: { projectId: string; data: { scan_type: string; target_id: string } }) =>
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
