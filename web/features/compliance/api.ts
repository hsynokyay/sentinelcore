// Phase-5 governance ops: compliance catalogs + mappings client.
//
// Backed by /api/v1/compliance/* endpoints. The API merges built-in
// (org_id IS NULL) and tenant-owned rows on the read path; mutation
// paths reject built-in modifications with 403.

import { api } from "@/lib/api-client";
import type {
  ComplianceCatalog,
  ComplianceControlRef,
  ComplianceItem,
  ComplianceMapping,
} from "@/lib/types";

export async function listCatalogs(): Promise<ComplianceCatalog[]> {
  const res = await api.get<{ catalogs: ComplianceCatalog[] }>(
    "/api/v1/compliance/catalogs",
  );
  return res.catalogs ?? [];
}

export async function listCatalogItems(catalogId: string): Promise<ComplianceItem[]> {
  const res = await api.get<{ items: ComplianceItem[] }>(
    `/api/v1/compliance/catalogs/${catalogId}/items`,
  );
  return res.items ?? [];
}

export async function listMappings(filters: {
  source_kind?: string;
  source_code?: string;
} = {}): Promise<ComplianceMapping[]> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v) params.set(k, String(v));
  });
  const qs = params.toString();
  const res = await api.get<{ mappings: ComplianceMapping[] }>(
    `/api/v1/compliance/mappings${qs ? `?${qs}` : ""}`,
  );
  return res.mappings ?? [];
}

export async function resolveControls(cwe: number): Promise<ComplianceControlRef[]> {
  const res = await api.get<{ controls: ComplianceControlRef[]; cwe_id: number }>(
    `/api/v1/compliance/resolve?cwe=${cwe}`,
  );
  return res.controls ?? [];
}

export async function createCatalog(input: {
  code: string;
  name: string;
  version: string;
  description?: string;
}): Promise<ComplianceCatalog> {
  return api.post<ComplianceCatalog>("/api/v1/compliance/catalogs", input);
}

export async function createCatalogItem(
  catalogId: string,
  input: { control_id: string; title: string; description?: string },
): Promise<ComplianceItem> {
  return api.post<ComplianceItem>(
    `/api/v1/compliance/catalogs/${catalogId}/items`,
    input,
  );
}

export async function createMapping(input: {
  source_kind: "cwe" | "owasp" | "internal";
  source_code: string;
  target_control_id: string;
  source_version?: string;
}): Promise<ComplianceMapping> {
  return api.post<ComplianceMapping>("/api/v1/compliance/mappings", input);
}

export async function deleteMapping(id: string): Promise<void> {
  await api.delete(`/api/v1/compliance/mappings/${id}`);
}
