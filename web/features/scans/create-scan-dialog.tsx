"use client";

import * as React from "react";
import { useEffect } from "react";
import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";

import { useProjects, useScanTargets, useCreateScan } from "./hooks";
import { useAuthProfiles } from "@/features/auth-profiles/hooks";
import { useSourceArtifacts } from "@/features/artifacts/hooks";
import { scanFormSchema, type ScanFormValues } from "./scan-form-schema";

interface CreateScanDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CreateScanDialog({ open, onOpenChange }: CreateScanDialogProps) {
  const {
    control,
    register,
    handleSubmit,
    watch,
    reset,
    setValue,
    formState: { errors },
  } = useForm<ScanFormValues>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: {
      project_id: "",
      scan_type: "sast",
      target_id: "",
      source_artifact_id: "",
      scan_profile: "standard",
      label: "",
      environment: "",
    },
  });

  const selectedProjectId = watch("project_id");
  const selectedScanType = watch("scan_type");
  const selectedTargetId = watch("target_id");

  const { data: projectsData, isLoading: loadingProjects } = useProjects();
  const { data: targetsData, isLoading: loadingTargets } = useScanTargets(selectedProjectId);
  const { data: authProfiles } = useAuthProfiles(selectedProjectId || undefined);
  const { data: artifacts } = useSourceArtifacts(selectedProjectId || undefined);
  const createScan = useCreateScan();

  const projects = projectsData?.projects ?? [];
  const targets = targetsData?.targets ?? [];
  const selectedTarget = targets.find((t) => t.id === selectedTargetId);
  const attachedProfile = selectedTarget?.auth_config_id
    ? (authProfiles ?? []).find((p) => p.id === selectedTarget.auth_config_id)
    : undefined;

  // Reset target/artifact when project changes
  useEffect(() => {
    setValue("target_id", "");
    setValue("source_artifact_id", "");
  }, [selectedProjectId, setValue]);

  // Reset artifact selection whenever scan type changes (only sast uses it).
  useEffect(() => {
    if (selectedScanType !== "sast") {
      setValue("source_artifact_id", "");
    }
  }, [selectedScanType, setValue]);

  // Reset form when dialog closes. We only depend on `open` because:
  // - `reset` from useForm is stable across renders.
  // - `createScan` (useMutation result) is a NEW object every render, so
  //   including it as a dep makes this effect run on every render — calling
  //   reset() on each render starves the main thread and blocks Next.js
  //   client-side route transitions away from /scans (the bug we hit in prod).
  // We hold createScan in a ref so the effect can call .reset() without
  // re-subscribing.
  const createScanRef = React.useRef(createScan);
  createScanRef.current = createScan;
  useEffect(() => {
    if (!open) {
      reset();
      createScanRef.current.reset();
    }
  }, [open, reset]);

  const onSubmit = (values: ScanFormValues) => {
    const {
      project_id,
      scan_type,
      target_id,
      source_artifact_id,
      scan_profile,
      label,
      environment,
    } = values;

    const configOverride: { label?: string; environment?: string } = {};
    if (label) configOverride.label = label;
    if (environment) configOverride.environment = environment;

    createScan.mutate(
      {
        projectId: project_id,
        data: {
          scan_type,
          target_id: target_id || undefined,
          source_artifact_id: source_artifact_id || undefined,
          scan_profile,
          config_override: Object.keys(configOverride).length > 0 ? configOverride : undefined,
        },
      },
      {
        onSuccess: () => {
          toast.success("Scan created successfully");
          onOpenChange(false);
        },
        onError: (error) => {
          toast.error("Failed to create scan", {
            description: error instanceof Error ? error.message : "Unknown error",
          });
        },
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Scan</DialogTitle>
          <DialogDescription>
            Configure and launch a new security scan.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {/* Project */}
          <div className="space-y-1.5">
            <Label>Project</Label>
            <Controller
              control={control}
              name="project_id"
              render={({ field }) => (
                <Select
                  value={field.value}
                  onValueChange={field.onChange}
                  itemToStringLabel={(v) => {
                    const p = projects.find((p) => p.id === v);
                    return p ? (p.display_name || p.name) : "";
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder={loadingProjects ? "Loading..." : "Select project"} />
                  </SelectTrigger>
                  <SelectContent>
                    {projects.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.display_name || p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
            {errors.project_id && (
              <p className="text-xs text-destructive">{errors.project_id.message}</p>
            )}
          </div>

          {/* Scan Type */}
          <div className="space-y-1.5">
            <Label>Scan Type</Label>
            <Controller
              control={control}
              name="scan_type"
              render={({ field }) => (
                <Select
                  value={field.value}
                  onValueChange={field.onChange}
                  itemToStringLabel={(v) => {
                    if (v === "sast") return "SAST";
                    if (v === "dast") return "DAST";
                    if (v === "full") return "SAST + DAST (full)";
                    return String(v);
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select scan type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sast">SAST</SelectItem>
                    <SelectItem value="dast">DAST</SelectItem>
                    <SelectItem value="full">SAST + DAST (full)</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
            {errors.scan_type && (
              <p className="text-xs text-destructive">{errors.scan_type.message}</p>
            )}
          </div>

          {/*
            Input selection is driven by scan_type:
              • dast  → Target is required
              • full  → Target is required (SAST component reuses the target's repo if any)
              • sast  → Source Artifact (primary) OR Target (legacy)
          */}
          {(selectedScanType === "dast" || selectedScanType === "full") && (
            <div className="space-y-1.5">
              <Label>Target</Label>
              <Controller
                control={control}
                name="target_id"
                render={({ field }) => (
                  <Select
                    value={field.value}
                    onValueChange={field.onChange}
                    disabled={!selectedProjectId}
                    itemToStringLabel={(v) => {
                      const t = targets.find((t) => t.id === v);
                      return t ? (t.label || t.base_url) : "";
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue
                        placeholder={
                          !selectedProjectId
                            ? "Select a project first"
                            : loadingTargets
                              ? "Loading..."
                              : targets.length === 0
                                ? "No targets in this project — add one from Targets"
                                : "Select target"
                        }
                      />
                    </SelectTrigger>
                    <SelectContent>
                      {targets.map((t) => (
                        <SelectItem key={t.id} value={t.id}>
                          {t.label || t.base_url}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
              {errors.target_id && (
                <p className="text-xs text-destructive">
                  {errors.target_id.message}
                </p>
              )}
            </div>
          )}

          {selectedScanType === "sast" && (
            <>
              <div className="space-y-1.5">
                <Label>Source Artifact</Label>
                <Controller
                  control={control}
                  name="source_artifact_id"
                  render={({ field }) => (
                    <Select
                      value={field.value || "__none__"}
                      onValueChange={(v) =>
                        field.onChange(v === "__none__" ? "" : v)
                      }
                      disabled={!selectedProjectId}
                      itemToStringLabel={(v) => {
                        if (v === "__none__") return "None";
                        const a = (artifacts ?? []).find((a) => a.id === v);
                        return a ? `${a.name} (${a.entry_count} files)` : "";
                      }}
                    >
                      <SelectTrigger>
                        <SelectValue
                          placeholder={
                            !selectedProjectId
                              ? "Select a project first"
                              : (artifacts ?? []).length === 0
                                ? "No artifacts — upload one from Source Artifacts"
                                : "Select source artifact"
                          }
                        />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__none__">None</SelectItem>
                        {(artifacts ?? []).map((a) => (
                          <SelectItem key={a.id} value={a.id}>
                            {a.name} ({a.entry_count} files)
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                />
                <p className="text-xs text-muted-foreground">
                  Upload source bundles from the{" "}
                  <span className="underline">Source Artifacts</span> page.
                </p>
              </div>

              {/* Target fallback for SAST — collapsed to a single optional line */}
              <div className="space-y-1.5">
                <Label>
                  Or scan a target{" "}
                  <span className="text-muted-foreground font-normal">
                    (legacy git-based SAST)
                  </span>
                </Label>
                <Controller
                  control={control}
                  name="target_id"
                  render={({ field }) => (
                    <Select
                      value={field.value || "__none__"}
                      onValueChange={(v) =>
                        field.onChange(v === "__none__" ? "" : v)
                      }
                      disabled={!selectedProjectId}
                      itemToStringLabel={(v) => {
                        if (v === "__none__") return "None";
                        const t = targets.find((t) => t.id === v);
                        return t ? (t.label || t.base_url) : "";
                      }}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="None" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__none__">None</SelectItem>
                        {targets.map((t) => (
                          <SelectItem key={t.id} value={t.id}>
                            {t.label || t.base_url}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                />
                {errors.target_id && (
                  <p className="text-xs text-destructive">
                    {errors.target_id.message}
                  </p>
                )}
              </div>
            </>
          )}

          {/* Scan Mode — DAST/full only. SAST runs at a fixed intensity. */}
          {(selectedScanType === "dast" || selectedScanType === "full") && (
            <div className="space-y-1.5">
              <Label>Scan Mode</Label>
              <Controller
                control={control}
                name="scan_profile"
                render={({ field }) => (
                  <Select
                    value={field.value}
                    onValueChange={field.onChange}
                    itemToStringLabel={(v) => {
                      if (v === "passive") return "Passive — observation only";
                      if (v === "standard") return "Standard — balanced active checks";
                      if (v === "aggressive") return "Aggressive — full active coverage";
                      return String(v);
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select scan mode" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="passive">
                        Passive — observation only
                      </SelectItem>
                      <SelectItem value="standard">
                        Standard — balanced active checks
                      </SelectItem>
                      <SelectItem value="aggressive">
                        Aggressive — full active coverage
                      </SelectItem>
                    </SelectContent>
                  </Select>
                )}
              />
            </div>
          )}

          {/* Label */}
          <div className="space-y-1.5">
            <Label>
              Label <span className="text-muted-foreground font-normal">(optional)</span>
            </Label>
            <Input placeholder="e.g. nightly-regression" {...register("label")} />
          </div>

          {/* Environment */}
          <div className="space-y-1.5">
            <Label>
              Environment <span className="text-muted-foreground font-normal">(optional)</span>
            </Label>
            <Input placeholder="e.g. staging, production" {...register("environment")} />
          </div>

          {/* Auth Profile (DAST/full only — attachment lives on the target) */}
          {(selectedScanType === "dast" || selectedScanType === "full") && (
            <div className="space-y-1.5">
              <Label>Auth Profile</Label>
              {selectedTarget ? (
                attachedProfile ? (
                  <div className="px-3 py-2 text-sm bg-muted rounded-md border">
                    <div className="font-medium">{attachedProfile.name}</div>
                    <div className="text-xs text-muted-foreground">
                      {attachedProfile.auth_type.replace("_", " ")} · credentials{" "}
                      {attachedProfile.has_credentials ? "stored" : "missing"}
                    </div>
                  </div>
                ) : (
                  <div className="px-3 py-2 text-sm text-muted-foreground bg-muted rounded-md border">
                    No auth profile attached to this target — scan will run
                    unauthenticated.
                  </div>
                )
              ) : (
                <div className="px-3 py-2 text-sm text-muted-foreground bg-muted rounded-md border">
                  Select a target to see its auth profile.
                </div>
              )}
              <p className="text-xs text-muted-foreground">
                Attach or change auth profiles from the Targets page.
              </p>
            </div>
          )}

          {/* Error */}
          {createScan.isError && (
            <p className="text-sm text-destructive">
              {createScan.error instanceof Error ? createScan.error.message : "Failed to create scan"}
            </p>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={createScan.isPending}>
              {createScan.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1" />}
              {createScan.isPending ? "Creating..." : "Create Scan"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
