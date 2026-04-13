import { api } from "@/lib/api-client";
import type { Scan, Project, ScanTarget } from "@/lib/types";

export interface ScanFilters {
  project_id?: string;
  status?: string;
  scan_type?: string;
  limit?: number;
  offset?: number;
}

export interface ScansResponse {
  scans: Scan[];
  limit: number;
  offset: number;
}

export async function getScans(filters: ScanFilters = {}): Promise<ScansResponse> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  // TODO: Replace with dedicated scans list endpoint when available
  return api.get<ScansResponse>(`/api/v1/scans?${params.toString()}`);
}

export async function getScan(id: string): Promise<{ scan: Scan }> {
  return api.get<{ scan: Scan }>(`/api/v1/scans/${id}`);
}

export async function getProjects(): Promise<{ projects: Project[] }> {
  return api.get<{ projects: Project[] }>("/api/v1/projects");
}

export async function getScanTargets(projectId: string): Promise<{ targets: ScanTarget[] }> {
  const res = await api.get<{ scan_targets?: ScanTarget[]; targets?: ScanTarget[] }>(
    `/api/v1/projects/${projectId}/scan-targets`,
  );
  return { targets: res.scan_targets ?? res.targets ?? [] };
}

export interface CreateScanPayload {
  scan_type: string;
  target_id?: string;
  source_artifact_id?: string;
  scan_profile?: string;
  config_override?: { label?: string; environment?: string };
}

export async function createScan(
  projectId: string,
  data: CreateScanPayload,
): Promise<{ scan: Scan }> {
  return api.post<{ scan: Scan }>(`/api/v1/projects/${projectId}/scans`, data);
}

export async function cancelScan(id: string): Promise<void> {
  await api.post(`/api/v1/scans/${id}/cancel`);
}
