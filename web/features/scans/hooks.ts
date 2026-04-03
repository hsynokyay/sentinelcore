import { useQuery } from "@tanstack/react-query";
import { getScans, getScan, type ScanFilters } from "./api";

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
