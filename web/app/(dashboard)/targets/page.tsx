"use client";

import { useState, useMemo } from "react";
import { Plus } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/data/page-header";
import { ErrorState } from "@/components/data/error-state";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";

import { useProjects } from "@/features/scans/hooks";
import { useTargets, useDeleteTarget } from "@/features/targets/hooks";
import { TargetsTable } from "@/features/targets/targets-table";
import { TargetFormDialog } from "@/features/targets/target-form-dialog";
import type { ScanTarget } from "@/lib/types";

export default function TargetsPage() {
  const { data: projectsData, isLoading: loadingProjects } = useProjects();
  const projects = useMemo(() => projectsData?.projects ?? [], [projectsData]);
  const [projectId, setProjectId] = useState<string>("");

  // Default to first project once loaded.
  if (!projectId && projects.length > 0) {
    setProjectId(projects[0].id);
  }

  const {
    data: targets,
    isLoading,
    isError,
    refetch,
  } = useTargets(projectId || undefined);
  const deleteMut = useDeleteTarget(projectId || undefined);

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<ScanTarget | undefined>(undefined);
  const [deleting, setDeleting] = useState<ScanTarget | undefined>(undefined);

  const openCreate = () => {
    setEditing(undefined);
    setFormOpen(true);
  };
  const openEdit = (t: ScanTarget) => {
    setEditing(t);
    setFormOpen(true);
  };

  const confirmDelete = () => {
    if (!deleting) return;
    deleteMut.mutate(deleting.id, {
      onSuccess: () => {
        toast.success(`Deleted target ${deleting.label || deleting.base_url}`);
        setDeleting(undefined);
      },
      onError: (err) => {
        toast.error("Failed to delete target", {
          description: err instanceof Error ? err.message : "Unknown error",
        });
      },
    });
  };

  return (
    <div>
      <PageHeader
        title="Scan Targets"
        description="Web apps, APIs, and GraphQL endpoints that scans will run against"
        actions={
          <Button onClick={openCreate} disabled={!projectId}>
            <Plus className="h-4 w-4 mr-1" />
            New Target
          </Button>
        }
      />

      <div className="flex items-center gap-2 mb-4 max-w-xs">
        <Select
          value={projectId}
          onValueChange={setProjectId}
          disabled={loadingProjects}
        >
          <SelectTrigger>
            <SelectValue
              placeholder={loadingProjects ? "Loading…" : "Select project"}
            />
          </SelectTrigger>
          <SelectContent>
            {projects.map((p) => (
              <SelectItem key={p.id} value={p.id}>
                {p.display_name || p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isError ? (
        <ErrorState
          message="Failed to load targets"
          onRetry={() => refetch()}
        />
      ) : (
        <TargetsTable
          targets={targets ?? []}
          isLoading={isLoading}
          onEdit={openEdit}
          onDelete={(t) => setDeleting(t)}
        />
      )}

      {projectId && (
        <TargetFormDialog
          open={formOpen}
          onOpenChange={setFormOpen}
          existing={editing}
          lockProjectId={editing ? undefined : projectId}
        />
      )}

      <Dialog open={!!deleting} onOpenChange={(v) => !v && setDeleting(undefined)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete target?</DialogTitle>
            <DialogDescription>
              This will permanently remove{" "}
              <span className="font-medium text-foreground">
                {deleting?.label || deleting?.base_url}
              </span>
              . Targets referenced by existing scans cannot be deleted.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleting(undefined)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDelete}
              disabled={deleteMut.isPending}
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
