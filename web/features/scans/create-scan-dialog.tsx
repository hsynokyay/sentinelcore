"use client";

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
      scan_type: "SAST",
      target_id: "",
      scan_profile: "standard",
      label: "",
      environment: "",
    },
  });

  const selectedProjectId = watch("project_id");

  const { data: projectsData, isLoading: loadingProjects } = useProjects();
  const { data: targetsData, isLoading: loadingTargets } = useScanTargets(selectedProjectId);
  const createScan = useCreateScan();

  const projects = projectsData?.projects ?? [];
  const targets = targetsData?.targets ?? [];

  // Reset target when project changes
  useEffect(() => {
    setValue("target_id", "");
  }, [selectedProjectId, setValue]);

  // Reset form when dialog closes
  useEffect(() => {
    if (!open) {
      reset();
      createScan.reset();
    }
  }, [open, reset, createScan]);

  const onSubmit = (values: ScanFormValues) => {
    const { project_id, scan_type, target_id, scan_profile, label, environment } = values;

    const configOverride: { label?: string; environment?: string } = {};
    if (label) configOverride.label = label;
    if (environment) configOverride.environment = environment;

    createScan.mutate(
      {
        projectId: project_id,
        data: {
          scan_type,
          target_id,
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
                <Select value={field.value} onValueChange={field.onChange}>
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
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select scan type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="SAST">SAST</SelectItem>
                    <SelectItem value="DAST">DAST</SelectItem>
                    <SelectItem value="SCA">SCA</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
            {errors.scan_type && (
              <p className="text-xs text-destructive">{errors.scan_type.message}</p>
            )}
          </div>

          {/* Target */}
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
                >
                  <SelectTrigger>
                    <SelectValue
                      placeholder={
                        !selectedProjectId
                          ? "Select a project first"
                          : loadingTargets
                            ? "Loading..."
                            : "Select target"
                      }
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {targets.map((t) => (
                      <SelectItem key={t.id} value={t.id}>
                        {t.label || t.identifier}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
            {errors.target_id && (
              <p className="text-xs text-destructive">{errors.target_id.message}</p>
            )}
          </div>

          {/* Scan Mode */}
          <div className="space-y-1.5">
            <Label>Scan Mode</Label>
            <Controller
              control={control}
              name="scan_profile"
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select scan mode" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="passive">Passive</SelectItem>
                    <SelectItem value="standard">Standard</SelectItem>
                    <SelectItem value="aggressive">Aggressive</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
          </div>

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

          {/* Auth Profile (disabled) */}
          <div className="space-y-1.5">
            <Label className="text-muted-foreground">Auth Profile</Label>
            <div className="relative group">
              <Select disabled>
                <SelectTrigger className="opacity-50">
                  <SelectValue placeholder="Not configured" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_none">None</SelectItem>
                </SelectContent>
              </Select>
              <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-foreground text-background text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap">
                Coming soon
              </div>
            </div>
          </div>

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
