"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { SourceArtifact } from "@/lib/types";
import {
  listSourceArtifacts,
  deleteSourceArtifact,
  uploadSourceArtifact,
  type UploadProgress,
} from "./api";

export function useSourceArtifacts(projectId: string | undefined) {
  return useQuery<SourceArtifact[]>({
    queryKey: ["source-artifacts", projectId],
    queryFn: () => listSourceArtifacts(projectId!),
    enabled: !!projectId,
  });
}

export function useUploadSourceArtifact(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: {
      file: File;
      name?: string;
      description?: string;
      onProgress?: (p: UploadProgress) => void;
    }) =>
      uploadSourceArtifact(projectId!, vars.file, {
        name: vars.name,
        description: vars.description,
        onProgress: vars.onProgress,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["source-artifacts", projectId] }),
  });
}

export function useDeleteSourceArtifact(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteSourceArtifact(id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["source-artifacts", projectId] }),
  });
}
