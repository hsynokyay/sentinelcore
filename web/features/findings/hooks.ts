import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getFindings, getFinding, updateFindingStatus, type FindingFilters } from "./api";

export function useFindings(filters: FindingFilters = {}) {
  return useQuery({
    queryKey: ["findings", filters],
    queryFn: () => getFindings(filters),
  });
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: ["findings", id],
    queryFn: () => getFinding(id),
    enabled: !!id,
  });
}

export function useTriageFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, reason }: { id: string; status: string; reason: string }) =>
      updateFindingStatus(id, status, reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });
}
