// React Query hooks for the compliance API. Same cache-invalidation
// pattern as web/features/governance/hooks.ts.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createCatalog,
  createCatalogItem,
  createMapping,
  deleteMapping,
  listCatalogItems,
  listCatalogs,
  listMappings,
  resolveControls,
} from "./api";

export function useComplianceCatalogs() {
  return useQuery({
    queryKey: ["compliance-catalogs"],
    queryFn: () => listCatalogs(),
  });
}

export function useComplianceCatalogItems(catalogId: string | undefined) {
  return useQuery({
    queryKey: ["compliance-catalog-items", catalogId],
    queryFn: () => listCatalogItems(catalogId as string),
    enabled: Boolean(catalogId),
  });
}

export function useComplianceMappings(filters: {
  source_kind?: string;
  source_code?: string;
} = {}) {
  return useQuery({
    queryKey: ["compliance-mappings", filters],
    queryFn: () => listMappings(filters),
  });
}

export function useResolveControls(cwe: number | undefined) {
  return useQuery({
    queryKey: ["compliance-resolve", cwe],
    queryFn: () => resolveControls(cwe as number),
    enabled: typeof cwe === "number" && cwe > 0,
  });
}

export function useCreateCatalog() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createCatalog,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance-catalogs"] }),
  });
}

export function useCreateCatalogItem(catalogId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { control_id: string; title: string; description?: string }) =>
      createCatalogItem(catalogId, input),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["compliance-catalog-items", catalogId] }),
  });
}

export function useCreateMapping() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createMapping,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance-mappings"] }),
  });
}

export function useDeleteMapping() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteMapping,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance-mappings"] }),
  });
}
