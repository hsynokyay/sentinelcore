import { api } from "@/lib/api-client";
import type { ApprovalRequest, OrgSettings } from "@/lib/types";

export interface ApprovalFilters {
  status?: string;
  limit?: number;
  offset?: number;
}

export interface ApprovalsResponse {
  requests: ApprovalRequest[];
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

export async function getSettings(): Promise<OrgSettings> {
  return api.get<OrgSettings>("/api/v1/governance/settings");
}

export async function updateSettings(settings: Partial<OrgSettings>): Promise<OrgSettings> {
  return api.put<OrgSettings>("/api/v1/governance/settings", settings);
}
