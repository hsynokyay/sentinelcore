import { api } from "@/lib/api-client";
import type { ApprovalRequest, EmergencyStop, OrgSettings } from "@/lib/types";

export interface ApprovalFilters {
  status?: string;
  limit?: number;
  offset?: number;
}

export interface ApprovalsResponse {
  approvals: ApprovalRequest[];
  limit: number;
  offset: number;
}

export async function getApprovals(filters: ApprovalFilters = {}): Promise<ApprovalsResponse> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  return api.get<ApprovalsResponse>(`/api/v1/governance/approvals?${params.toString()}`);
}

export async function decideApproval(id: string, decision: "approved" | "rejected", reason: string) {
  return api.post(`/api/v1/governance/approvals/${id}/decide`, { decision, reason });
}

// Phase-5 two-person approval endpoint. Records a per-approver decision against
// governance.approval_decisions; the controlplane auto-executes the gated
// transition when the approval threshold is met.
export interface CreateApprovalRequestBody {
  request_type: string;
  resource_type: string;
  resource_id: string;
  reason: string;
  required_approvals: number;
  target_transition: string;
  project_id?: string;
  team_id?: string;
}

export async function createApprovalRequest(body: CreateApprovalRequestBody): Promise<ApprovalRequest> {
  return api.post<ApprovalRequest>("/api/v1/governance/approvals", body);
}

export async function submitApprovalDecision(
  id: string,
  decision: "approve" | "reject",
  reason: string,
): Promise<ApprovalRequest> {
  return api.post<ApprovalRequest>(`/api/v1/governance/approvals/${id}/decisions`, { decision, reason });
}

export async function getSettings(): Promise<OrgSettings> {
  return api.get<OrgSettings>("/api/v1/governance/settings");
}

export async function updateSettings(settings: Partial<OrgSettings>): Promise<OrgSettings> {
  return api.put<OrgSettings>("/api/v1/governance/settings", settings);
}

export async function activateEmergencyStop(
  scope: string,
  scopeId: string | undefined,
  reason: string,
): Promise<{ stop: EmergencyStop }> {
  return api.post<{ stop: EmergencyStop }>("/api/v1/governance/emergency-stop", {
    scope,
    scope_id: scopeId,
    reason,
  });
}

export async function liftEmergencyStop(stopId: string): Promise<void> {
  await api.post("/api/v1/governance/emergency-stop/lift", { stop_id: stopId });
}

export async function listActiveEmergencyStops(): Promise<{ stops: EmergencyStop[] }> {
  return api.get<{ stops: EmergencyStop[] }>("/api/v1/governance/emergency-stop/active");
}
