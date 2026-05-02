"use client";

import { useEffect } from "react";
import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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

import { useProjects } from "@/features/scans/hooks";
import { useAuthProfiles } from "@/features/auth-profiles/hooks";
import { useCreateTarget, useUpdateTarget } from "./hooks";
import {
  targetFormSchema,
  type TargetFormValues,
} from "./target-form-schema";
import type { ScanTarget, CreateScanTargetPayload } from "@/lib/types";

interface TargetFormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  // When provided, the dialog operates in "edit" mode. project_id is locked.
  existing?: ScanTarget;
  // When provided (create mode), pre-selects a project and locks the field.
  lockProjectId?: string;
}

export function TargetFormDialog({
  open,
  onOpenChange,
  existing,
  lockProjectId,
}: TargetFormDialogProps) {
  const isEdit = !!existing;
  const { data: projectsData } = useProjects();
  const projects = projectsData?.projects ?? [];

  const {
    control,
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TargetFormValues>({
    resolver: zodResolver(targetFormSchema),
    defaultValues: {
      project_id: existing?.project_id ?? lockProjectId ?? "",
      target_type: (existing?.target_type as TargetFormValues["target_type"]) ?? "web_app",
      base_url: existing?.base_url ?? "",
      label: existing?.label ?? "",
      environment: existing?.environment ?? "",
      notes: existing?.notes ?? "",
      allowed_domains: existing?.allowed_domains?.join(", ") ?? "",
      max_rps: existing?.max_rps ? String(existing.max_rps) : "",
      auth_config_id: existing?.auth_config_id ?? "",
    },
  });

  // Reset form state whenever the dialog opens or the existing row changes.
  useEffect(() => {
    if (open) {
      reset({
        project_id: existing?.project_id ?? lockProjectId ?? "",
        target_type: (existing?.target_type as TargetFormValues["target_type"]) ?? "web_app",
        base_url: existing?.base_url ?? "",
        label: existing?.label ?? "",
        environment: existing?.environment ?? "",
        notes: existing?.notes ?? "",
        allowed_domains: existing?.allowed_domains?.join(", ") ?? "",
        max_rps: existing?.max_rps ? String(existing.max_rps) : "",
        auth_config_id: existing?.auth_config_id ?? "",
      });
    }
  }, [open, existing, lockProjectId, reset]);

  // Watch project_id so we can fetch its auth profiles for the attach selector.
  const watchedProjectId = (existing?.project_id ?? lockProjectId) || undefined;
  const { data: authProfiles } = useAuthProfiles(watchedProjectId);

  const createMut = useCreateTarget(
    lockProjectId ?? existing?.project_id,
  );
  const updateMut = useUpdateTarget(existing?.project_id);

  const onSubmit = (values: TargetFormValues) => {
    const payload: CreateScanTargetPayload = {
      target_type: values.target_type,
      base_url: values.base_url,
      label: values.label || undefined,
      environment: values.environment || undefined,
      notes: values.notes || undefined,
      max_rps: values.max_rps ? parseInt(values.max_rps, 10) : undefined,
      allowed_domains: values.allowed_domains
        ? values.allowed_domains
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : undefined,
      // "" from the select means "detach". undefined means "leave alone".
      auth_config_id:
        values.auth_config_id === undefined ? undefined : values.auth_config_id,
    };

    if (isEdit && existing) {
      updateMut.mutate(
        { id: existing.id, payload },
        {
          onSuccess: () => {
            toast.success("Target updated");
            onOpenChange(false);
          },
          onError: (err) =>
            toast.error("Failed to update target", {
              description: err instanceof Error ? err.message : "Unknown error",
            }),
        },
      );
    } else {
      createMut.mutate(payload, {
        onSuccess: () => {
          toast.success("Target created");
          onOpenChange(false);
        },
        onError: (err) =>
          toast.error("Failed to create target", {
            description: err instanceof Error ? err.message : "Unknown error",
          }),
      });
    }
  };

  const isPending = createMut.isPending || updateMut.isPending;
  const projectLocked = isEdit || !!lockProjectId;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit Target" : "New Scan Target"}</DialogTitle>
          <DialogDescription>
            Define the application, API, or GraphQL endpoint that scans will run
            against. Scope is enforced by allowed domains and rate limits.
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
                  disabled={projectLocked}
                  itemToStringLabel={(v) => {
                    const p = projects.find((p) => p.id === v);
                    return p ? (p.display_name || p.name) : "";
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select project" />
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
              <p className="text-xs text-destructive">
                {errors.project_id.message}
              </p>
            )}
          </div>

          {/* Type */}
          <div className="space-y-1.5">
            <Label>Target Type</Label>
            <Controller
              control={control}
              name="target_type"
              render={({ field }) => (
                <Select
                  value={field.value}
                  onValueChange={field.onChange}
                  disabled={isEdit}
                  itemToStringLabel={(v) => {
                    if (v === "web_app") return "Web Application";
                    if (v === "api") return "REST API";
                    if (v === "graphql") return "GraphQL API";
                    return String(v);
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select target type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="web_app">Web Application</SelectItem>
                    <SelectItem value="api">REST API</SelectItem>
                    <SelectItem value="graphql">GraphQL API</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
            {isEdit && (
              <p className="text-xs text-muted-foreground">
                Target type is immutable after creation.
              </p>
            )}
          </div>

          {/* Base URL */}
          <div className="space-y-1.5">
            <Label>Base URL</Label>
            <Input
              placeholder="https://app.example.com"
              {...register("base_url")}
            />
            {errors.base_url && (
              <p className="text-xs text-destructive">
                {errors.base_url.message}
              </p>
            )}
          </div>

          {/* Label + environment row */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Label</Label>
              <Input placeholder="prod-app" {...register("label")} />
            </div>
            <div className="space-y-1.5">
              <Label>Environment</Label>
              <Input placeholder="production" {...register("environment")} />
            </div>
          </div>

          {/* Allowed domains */}
          <div className="space-y-1.5">
            <Label>Allowed Domains</Label>
            <Input
              placeholder="app.example.com, api.example.com"
              {...register("allowed_domains")}
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated. Defaults to the base URL host.
            </p>
          </div>

          {/* Max RPS */}
          <div className="space-y-1.5">
            <Label>
              Max requests/sec{" "}
              <span className="text-muted-foreground font-normal">
                (default 10)
              </span>
            </Label>
            <Input
              type="number"
              min={1}
              max={500}
              placeholder="10"
              {...register("max_rps")}
            />
            {errors.max_rps && (
              <p className="text-xs text-destructive">
                {errors.max_rps.message as string}
              </p>
            )}
          </div>

          {/* Notes */}
          <div className="space-y-1.5">
            <Label>
              Notes{" "}
              <span className="text-muted-foreground font-normal">
                (optional)
              </span>
            </Label>
            <Textarea rows={2} {...register("notes")} />
          </div>

          {/* Auth profile attachment */}
          <div className="space-y-1.5">
            <Label>
              Auth Profile{" "}
              <span className="text-muted-foreground font-normal">
                (optional — for authenticated DAST)
              </span>
            </Label>
            <Controller
              control={control}
              name="auth_config_id"
              render={({ field }) => (
                <Select
                  value={field.value || "__none__"}
                  onValueChange={(v) =>
                    field.onChange(v === "__none__" ? "" : v)
                  }
                  itemToStringLabel={(v) => {
                    if (v === "__none__") return "None";
                    const p = (authProfiles ?? []).find((p) => p.id === v);
                    return p ? `${p.name} — ${p.auth_type.replace("_", " ")}` : "";
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="None" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__">None</SelectItem>
                    {(authProfiles ?? []).map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.name} — {p.auth_type.replace("_", " ")}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending && <Loader2 className="h-4 w-4 animate-spin mr-1" />}
              {isEdit ? "Save" : "Create Target"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
