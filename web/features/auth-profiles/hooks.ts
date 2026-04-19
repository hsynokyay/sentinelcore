"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AuthProfile, CreateAuthProfilePayload } from "@/lib/types";
import {
  listAuthProfiles,
  getAuthProfile,
  createAuthProfile,
  updateAuthProfile,
  deleteAuthProfile,
} from "./api";

export function useAuthProfiles(projectId: string | undefined) {
  return useQuery<AuthProfile[]>({
    queryKey: ["auth-profiles", projectId],
    queryFn: () => listAuthProfiles(projectId!),
    enabled: !!projectId,
  });
}

export function useAuthProfile(id: string | undefined) {
  return useQuery<AuthProfile>({
    queryKey: ["auth-profile", id],
    queryFn: () => getAuthProfile(id!),
    enabled: !!id,
  });
}

export function useCreateAuthProfile(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateAuthProfilePayload) =>
      createAuthProfile(projectId!, payload),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["auth-profiles", projectId] }),
  });
}

export function useUpdateAuthProfile(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: Partial<CreateAuthProfilePayload>;
    }) => updateAuthProfile(id, payload),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["auth-profiles", projectId] });
      qc.invalidateQueries({ queryKey: ["auth-profile", vars.id] });
    },
  });
}

export function useDeleteAuthProfile(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteAuthProfile(id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["auth-profiles", projectId] }),
  });
}
