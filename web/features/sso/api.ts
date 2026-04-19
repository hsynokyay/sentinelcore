import { api } from "@/lib/api-client";
import type {
  SSOEnabledProvider,
  SSOGroupMapping,
  SSOGroupMappingPayload,
  SSOLoginEvent,
  SSOProvider,
  SSOProviderCreatePayload,
  SSOProviderUpdatePayload,
} from "./types";

export async function listSSOProviders(): Promise<SSOProvider[]> {
  const res = await api.get<{ providers: SSOProvider[] }>("/api/v1/sso/providers");
  return res.providers ?? [];
}

export async function getSSOProvider(id: string): Promise<SSOProvider> {
  return api.get<SSOProvider>(`/api/v1/sso/providers/${id}`);
}

export async function createSSOProvider(
  payload: SSOProviderCreatePayload,
): Promise<{ id: string }> {
  return api.post<{ id: string }>("/api/v1/sso/providers", payload);
}

export async function updateSSOProvider(
  id: string,
  payload: SSOProviderUpdatePayload,
): Promise<void> {
  await api.patch(`/api/v1/sso/providers/${id}`, payload);
}

export async function deleteSSOProvider(id: string): Promise<void> {
  await api.delete(`/api/v1/sso/providers/${id}`);
}

export async function listSSOMappings(
  providerId: string,
): Promise<SSOGroupMapping[]> {
  const res = await api.get<{ mappings: SSOGroupMapping[] }>(
    `/api/v1/sso/providers/${providerId}/mappings`,
  );
  return res.mappings ?? [];
}

export async function createSSOMapping(
  providerId: string,
  payload: SSOGroupMappingPayload,
): Promise<{ id: string }> {
  return api.post<{ id: string }>(
    `/api/v1/sso/providers/${providerId}/mappings`,
    payload,
  );
}

export async function deleteSSOMapping(
  providerId: string,
  mappingId: string,
): Promise<void> {
  await api.delete(
    `/api/v1/sso/providers/${providerId}/mappings/${mappingId}`,
  );
}

// Public (pre-auth). Unknown orgs return { providers: [] } — same shape
// as known orgs with no providers — so the response cannot be used to
// enumerate org slugs.
export async function listEnabledSSOProviders(
  orgSlug: string,
): Promise<SSOEnabledProvider[]> {
  const res = await api.get<{ providers: SSOEnabledProvider[] }>(
    `/api/v1/auth/sso/enabled?org=${encodeURIComponent(orgSlug)}`,
  );
  return res.providers ?? [];
}

// Authenticated. If the current session started via SSO and the
// provider has sso_logout_enabled, the response includes `redirect`
// — callers should window.location = redirect to complete RP-Initiated
// Logout at the IdP.
export async function ssoLogout(providerId?: string): Promise<{ redirect?: string }> {
  return api.post<{ redirect?: string }>("/api/v1/auth/sso/logout", {
    provider_id: providerId ?? "",
  });
}

export async function listSSOLoginHistory(
  providerId: string,
  limit = 50,
): Promise<SSOLoginEvent[]> {
  const res = await api.get<{ events: SSOLoginEvent[] }>(
    `/api/v1/sso/providers/${providerId}/history?limit=${limit}`,
  );
  return res.events ?? [];
}
