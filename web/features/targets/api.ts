import { api } from "@/lib/api-client";
import type { ScanTarget, CreateScanTargetPayload } from "@/lib/types";

// List endpoint returns both keys during the Chunk 1 migration — prefer
// `scan_targets` but fall back to `targets` so this file stays compatible
// with the transition release.
interface ListResponse {
  scan_targets?: ScanTarget[];
  targets?: ScanTarget[];
}

export async function listTargets(projectId: string): Promise<ScanTarget[]> {
  const res = await api.get<ListResponse>(
    `/api/v1/projects/${projectId}/scan-targets`,
  );
  return res.scan_targets ?? res.targets ?? [];
}

export async function getTarget(id: string): Promise<ScanTarget> {
  const res = await api.get<{ scan_target: ScanTarget }>(
    `/api/v1/scan-targets/${id}`,
  );
  return res.scan_target;
}

export async function createTarget(
  projectId: string,
  payload: CreateScanTargetPayload,
): Promise<ScanTarget> {
  const res = await api.post<{ scan_target: ScanTarget }>(
    `/api/v1/projects/${projectId}/scan-targets`,
    payload,
  );
  return res.scan_target;
}

export async function updateTarget(
  id: string,
  payload: Partial<CreateScanTargetPayload>,
): Promise<ScanTarget> {
  const res = await api.patch<{ scan_target: ScanTarget }>(
    `/api/v1/scan-targets/${id}`,
    payload,
  );
  return res.scan_target;
}

export async function deleteTarget(id: string): Promise<void> {
  await api.delete(`/api/v1/scan-targets/${id}`);
}
