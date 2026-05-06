import { api } from "@/lib/api-client";
import type {
  ApprovalRequest,
  EmergencyStop,
  OrgSettings,
  ProjectSLAPolicy,
  SLADashboard,
  SLAViolationSummary,
} from "@/lib/types";

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

// Phase-5 governance ops: SLA dashboard + per-project policy editor.

export async function getSLADashboard(warnDays = 7): Promise<SLADashboard> {
  return api.get<SLADashboard>(`/api/v1/governance/sla/dashboard?warn_days=${warnDays}`);
}

export interface SLAViolationsResponse {
  violations: SLAViolationSummary[];
  limit: number;
}

export async function listSLAViolations(
  status: "open" | "resolved" | "all" = "open",
  limit = 100,
): Promise<SLAViolationsResponse> {
  return api.get<SLAViolationsResponse>(
    `/api/v1/governance/sla/violations?status=${status}&limit=${limit}`,
  );
}

export async function getProjectSLAPolicy(projectId: string): Promise<ProjectSLAPolicy | null> {
  try {
    return await api.get<ProjectSLAPolicy>(`/api/v1/governance/sla/policies/${projectId}`);
  } catch (err) {
    // 404 means "no override" — fall back to org defaults at the call site.
    if (err instanceof Error && /404|not found/i.test(err.message)) return null;
    throw err;
  }
}

export async function putProjectSLAPolicy(
  projectId: string,
  slaDays: Record<string, number>,
): Promise<ProjectSLAPolicy> {
  return api.put<ProjectSLAPolicy>(`/api/v1/governance/sla/policies/${projectId}`, {
    sla_days: slaDays,
  });
}

export async function deleteProjectSLAPolicy(projectId: string): Promise<void> {
  await api.delete(`/api/v1/governance/sla/policies/${projectId}`);
}
