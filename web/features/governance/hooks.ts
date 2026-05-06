import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getApprovals,
  decideApproval,
  getSettings,
  updateSettings,
  activateEmergencyStop,
  liftEmergencyStop,
  listActiveEmergencyStops,
  createApprovalRequest,
  submitApprovalDecision,
  getSLADashboard,
  listSLAViolations,
  getProjectSLAPolicy,
  putProjectSLAPolicy,
  deleteProjectSLAPolicy,
  type ApprovalFilters,
  type CreateApprovalRequestBody,
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

// Phase-5 two-person rule mutations.
export function useCreateApprovalRequest() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateApprovalRequestBody) => createApprovalRequest(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });
}

export function useSubmitApprovalDecision() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, decision, reason }: { id: string; decision: "approve" | "reject"; reason: string }) =>
      submitApprovalDecision(id, decision, reason),
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

export function useEmergencyStops() {
  return useQuery({
    queryKey: ["emergency-stops"],
    queryFn: () => listActiveEmergencyStops(),
  });
}

export function useActivateEmergencyStop() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ scope, scopeId, reason }: { scope: string; scopeId?: string; reason: string }) =>
      activateEmergencyStop(scope, scopeId, reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["emergency-stops"] }),
  });
}

export function useLiftEmergencyStop() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (stopId: string) => liftEmergencyStop(stopId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["emergency-stops"] }),
  });
}

// Phase-5 governance ops: SLA dashboard + per-project policy editor.

export function useSLADashboard(warnDays = 7) {
  return useQuery({
    queryKey: ["sla-dashboard", warnDays],
    queryFn: () => getSLADashboard(warnDays),
    refetchInterval: 60_000,
  });
}

export function useSLAViolations(
  status: "open" | "resolved" | "all" = "open",
  limit = 100,
) {
  return useQuery({
    queryKey: ["sla-violations", status, limit],
    queryFn: () => listSLAViolations(status, limit),
  });
}

export function useProjectSLAPolicy(projectId: string | undefined) {
  return useQuery({
    queryKey: ["project-sla-policy", projectId],
    queryFn: () => (projectId ? getProjectSLAPolicy(projectId) : Promise.resolve(null)),
    enabled: !!projectId,
  });
}

export function usePutProjectSLAPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      projectId,
      slaDays,
    }: {
      projectId: string;
      slaDays: Record<string, number>;
    }) => putProjectSLAPolicy(projectId, slaDays),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["project-sla-policy", vars.projectId] });
      qc.invalidateQueries({ queryKey: ["sla-dashboard"] });
    },
  });
}

export function useDeleteProjectSLAPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (projectId: string) => deleteProjectSLAPolicy(projectId),
    onSuccess: (_, projectId) => {
      qc.invalidateQueries({ queryKey: ["project-sla-policy", projectId] });
      qc.invalidateQueries({ queryKey: ["sla-dashboard"] });
    },
  });
}
