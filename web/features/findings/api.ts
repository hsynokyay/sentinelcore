import { api } from "@/lib/api-client";
import type { FindingsResponse } from "@/lib/types";

export interface FindingFilters {
  project_id?: string;
  severity?: string;
  status?: string;
  finding_type?: string;
  limit?: number;
  offset?: number;
}

export async function getFindings(filters: FindingFilters = {}): Promise<FindingsResponse> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  return api.get<FindingsResponse>(`/api/v1/findings?${params.toString()}`);
}

export async function getFinding(id: string) {
  return api.get<{ finding: import("@/lib/types").Finding }>(`/api/v1/findings/${id}`);
}

export async function updateFindingStatus(id: string, status: string, reason: string) {
  return api.patch(`/api/v1/findings/${id}/status`, { status, reason });
}

export async function assignFinding(
  id: string,
  data: { assigned_to: string; note?: string },
): Promise<void> {
  await api.post(`/api/v1/findings/${id}/assign`, data);
}

export async function setLegalHold(
  id: string,
  hold: boolean,
  reason: string,
): Promise<void> {
  await api.post(`/api/v1/findings/${id}/legal-hold`, { hold, reason });
}
