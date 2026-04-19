import { api } from "@/lib/api-client";
import type { SurfaceEntry } from "@/lib/types";

export interface SurfaceFilters {
  project_id?: string;
  type?: string;
  exposure?: string;
  has_findings?: string;
  limit?: number;
  offset?: number;
}

export interface SurfaceResponse {
  entries: SurfaceEntry[];
  limit: number;
  offset: number;
}

export async function getSurfaceEntries(filters: SurfaceFilters = {}): Promise<SurfaceResponse> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  return api.get<SurfaceResponse>(`/api/v1/surface?${params.toString()}`);
}

export async function getSurfaceStats(projectId?: string) {
  const params = projectId ? `?project_id=${projectId}` : "";
  return api.get<{ stats: Array<{ type: string; exposure: string; count: number }> }>(`/api/v1/surface/stats${params}`);
}
