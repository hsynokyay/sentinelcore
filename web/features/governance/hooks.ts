import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getApprovals,
  decideApproval,
  getSettings,
  updateSettings,
  type ApprovalFilters,
} from "./api";
import type { OrgSettings } from "@/lib/types";

export function useApprovals(filters: ApprovalFilters = {}) {
  return useQuery({
    queryKey: ["approvals", filters],
    queryFn: () => getApprovals(filters),
  });
}

export function useDecideApproval() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, decision, reason }: { id: string; decision: "approved" | "rejected"; reason: string }) =>
      decideApproval(id, decision, reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });
}

export function useSettings() {
  return useQuery({
    queryKey: ["governance-settings"],
    queryFn: () => getSettings(),
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (settings: Partial<OrgSettings>) => updateSettings(settings),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["governance-settings"] }),
  });
}
