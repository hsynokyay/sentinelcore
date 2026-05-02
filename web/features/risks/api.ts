import { api } from "@/lib/api-client";
import type { RiskClusterDetail, RiskListFilters, RiskListResponse } from "@/lib/types";

export async function getRisks(filters: RiskListFilters): Promise<RiskListResponse> {
  const params = new URLSearchParams();
  params.set("project_id", filters.project_id);
  if (filters.status) params.set("status", filters.status);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.vuln_class) params.set("vuln_class", filters.vuln_class);
  if (filters.limit !== undefined) params.set("limit", String(filters.limit));
  if (filters.offset !== undefined) params.set("offset", String(filters.offset));
  return api.get<RiskListResponse>(`/api/v1/risks?${params.toString()}`);
}

export async function getRisk(id: string): Promise<{ risk: RiskClusterDetail }> {
  return api.get<{ risk: RiskClusterDetail }>(`/api/v1/risks/${id}`);
}

export async function resolveRisk(id: string, reason: string = ""): Promise<{ status: string }> {
  return api.post<{ status: string }>(`/api/v1/risks/${id}/resolve`, { reason });
}

export async function reopenRisk(id: string): Promise<{ status: string }> {
  return api.post<{ status: string }>(`/api/v1/risks/${id}/reopen`, {});
}

export async function muteRisk(id: string, until: string): Promise<{ status: string; muted_until: string }> {
  return api.post<{ status: string; muted_until: string }>(`/api/v1/risks/${id}/mute`, { until });
}

export async function rebuildRisks(projectId: string): Promise<{ status: string }> {
  return api.post<{ status: string }>(`/api/v1/projects/${projectId}/risks/rebuild`, {});
}
