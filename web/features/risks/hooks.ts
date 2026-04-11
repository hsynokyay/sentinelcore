import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getRisks,
  getRisk,
  resolveRisk,
  reopenRisk,
  muteRisk,
  rebuildRisks,
} from "./api";
import type { RiskListFilters } from "@/lib/types";

export function useRisks(filters: RiskListFilters) {
  return useQuery({
    queryKey: ["risks", filters],
    queryFn: () => getRisks(filters),
    enabled: Boolean(filters.project_id),
  });
}

export function useRisk(id: string | undefined) {
  return useQuery({
    queryKey: ["risks", id],
    queryFn: () => getRisk(id!),
    enabled: Boolean(id),
  });
}

export function useResolveRisk() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason?: string }) => resolveRisk(id, reason ?? ""),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["risks"] }),
  });
}

export function useReopenRisk() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => reopenRisk(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["risks"] }),
  });
}

export function useMuteRisk() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, until }: { id: string; until: string }) => muteRisk(id, until),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["risks"] }),
  });
}

export function useRebuildRisks() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (projectId: string) => rebuildRisks(projectId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["risks"] }),
  });
}
