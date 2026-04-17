"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createSSOMapping,
  createSSOProvider,
  deleteSSOMapping,
  deleteSSOProvider,
  getSSOProvider,
  listEnabledSSOProviders,
  listSSOLoginHistory,
  listSSOMappings,
  listSSOProviders,
  updateSSOProvider,
} from "./api";
import type {
  SSOEnabledProvider,
  SSOGroupMapping,
  SSOGroupMappingPayload,
  SSOLoginEvent,
  SSOProvider,
  SSOProviderCreatePayload,
  SSOProviderUpdatePayload,
} from "./types";

export function useSSOProviders() {
  return useQuery<SSOProvider[]>({
    queryKey: ["sso", "providers"],
    queryFn: listSSOProviders,
  });
}

export function useSSOProvider(id: string | undefined) {
  return useQuery<SSOProvider>({
    queryKey: ["sso", "provider", id],
    queryFn: () => getSSOProvider(id!),
    enabled: !!id,
  });
}

export function useCreateSSOProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: SSOProviderCreatePayload) => createSSOProvider(payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sso", "providers"] }),
  });
}

export function useUpdateSSOProvider(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: SSOProviderUpdatePayload) =>
      updateSSOProvider(id!, payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sso", "providers"] });
      qc.invalidateQueries({ queryKey: ["sso", "provider", id] });
    },
  });
}

export function useDeleteSSOProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteSSOProvider(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sso", "providers"] }),
  });
}

export function useSSOMappings(providerId: string | undefined) {
  return useQuery<SSOGroupMapping[]>({
    queryKey: ["sso", "mappings", providerId],
    queryFn: () => listSSOMappings(providerId!),
    enabled: !!providerId,
  });
}

export function useCreateSSOMapping(providerId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: SSOGroupMappingPayload) =>
      createSSOMapping(providerId!, payload),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["sso", "mappings", providerId] }),
  });
}

export function useDeleteSSOMapping(providerId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (mappingId: string) => deleteSSOMapping(providerId!, mappingId),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["sso", "mappings", providerId] }),
  });
}

// Public, used by the login page. Short staleTime so enable/disable
// toggles in settings are picked up within a minute.
export function useEnabledSSOProviders(orgSlug: string | undefined) {
  return useQuery<SSOEnabledProvider[]>({
    queryKey: ["sso", "enabled", orgSlug],
    queryFn: () => listEnabledSSOProviders(orgSlug!),
    enabled: !!orgSlug,
    staleTime: 60_000,
    retry: false,
  });
}

// Diagnostic history for a provider — last 50 attempts by default,
// max 200. The backing table is capped at 500 rows per provider by an
// AFTER INSERT trigger so there is no pagination — the latest always fits.
export function useSSOLoginHistory(
  providerId: string | undefined,
  limit = 50,
) {
  return useQuery<SSOLoginEvent[]>({
    queryKey: ["sso", "history", providerId, limit],
    queryFn: () => listSSOLoginHistory(providerId!, limit),
    enabled: !!providerId,
    refetchInterval: 10_000, // auto-refresh during an active test session
  });
}
