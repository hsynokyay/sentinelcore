"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ScanTarget, CreateScanTargetPayload } from "@/lib/types";
import {
  listTargets,
  getTarget,
  createTarget,
  updateTarget,
  deleteTarget,
} from "./api";

export function useTargets(projectId: string | undefined) {
  return useQuery<ScanTarget[]>({
    queryKey: ["targets", projectId],
    queryFn: () => listTargets(projectId!),
    enabled: !!projectId,
  });
}

export function useTarget(id: string | undefined) {
  return useQuery<ScanTarget>({
    queryKey: ["target", id],
    queryFn: () => getTarget(id!),
    enabled: !!id,
  });
}

export function useCreateTarget(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateScanTargetPayload) =>
      createTarget(projectId!, payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["targets", projectId] });
      qc.invalidateQueries({ queryKey: ["scan-targets", projectId] });
    },
  });
}

export function useUpdateTarget(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: Partial<CreateScanTargetPayload>;
    }) => updateTarget(id, payload),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["targets", projectId] });
      qc.invalidateQueries({ queryKey: ["target", vars.id] });
    },
  });
}

export function useDeleteTarget(projectId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteTarget(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["targets", projectId] });
    },
  });
}
