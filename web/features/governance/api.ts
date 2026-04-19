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

// Phase 9 §4.1: multi-approver routes. The old /decide endpoint
// stays on the server for backward compat, but new UI voting uses
// the FSM-gated /approve and /reject routes so step-up errors
// (requester vote, duplicate vote, terminal state) surface cleanly.
export async function decideApproval(id: string, decision: "approved" | "rejected", reason: string) {
  const path = decision === "approved" ? "approve" : "reject";
  return api.post(`/api/v1/governance/approvals/${id}/${path}`, { reason });
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
