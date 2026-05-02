import { api } from "@/lib/api-client";
import type { AuthProfile, CreateAuthProfilePayload } from "@/lib/types";

export async function listAuthProfiles(
  projectId: string,
): Promise<AuthProfile[]> {
  const res = await api.get<{ auth_profiles: AuthProfile[] }>(
    `/api/v1/projects/${projectId}/auth-profiles`,
  );
  return res.auth_profiles ?? [];
}

export async function getAuthProfile(id: string): Promise<AuthProfile> {
  const res = await api.get<{ auth_profile: AuthProfile }>(
    `/api/v1/auth-profiles/${id}`,
  );
  return res.auth_profile;
}

export async function createAuthProfile(
  projectId: string,
  payload: CreateAuthProfilePayload,
): Promise<AuthProfile> {
  const res = await api.post<{ auth_profile: AuthProfile }>(
    `/api/v1/projects/${projectId}/auth-profiles`,
    payload,
  );
  return res.auth_profile;
}

export async function updateAuthProfile(
  id: string,
  payload: Partial<CreateAuthProfilePayload>,
): Promise<AuthProfile> {
  const res = await api.patch<{ auth_profile: AuthProfile }>(
    `/api/v1/auth-profiles/${id}`,
    payload,
  );
  return res.auth_profile;
}

export async function deleteAuthProfile(id: string): Promise<void> {
  await api.delete(`/api/v1/auth-profiles/${id}`);
}
