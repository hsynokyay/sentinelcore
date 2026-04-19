"use client";

import { useState, useMemo } from "react";
import { Upload } from "lucide-react";
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
import {
  useSourceArtifacts,
  useDeleteSourceArtifact,
} from "@/features/artifacts/hooks";
import { ArtifactsTable } from "@/features/artifacts/artifacts-table";
import { ArtifactUploadDialog } from "@/features/artifacts/artifact-upload-dialog";
import type { SourceArtifact } from "@/lib/types";

export default function ArtifactsPage() {
  const { data: projectsData, isLoading: loadingProjects } = useProjects();
  const projects = useMemo(() => projectsData?.projects ?? [], [projectsData]);
  const [projectId, setProjectId] = useState<string>("");

  if (!projectId && projects.length > 0) {
    setProjectId(projects[0].id);
  }

  const {
    data: artifacts,
    isLoading,
    isError,
    refetch,
  } = useSourceArtifacts(projectId || undefined);
  const deleteMut = useDeleteSourceArtifact(projectId || undefined);

  const [uploadOpen, setUploadOpen] = useState(false);
  const [deleting, setDeleting] = useState<SourceArtifact | undefined>(
    undefined,
  );

  const confirmDelete = () => {
    if (!deleting) return;
    deleteMut.mutate(deleting.id, {
      onSuccess: () => {
        toast.success(`Deleted ${deleting.name}`);
        setDeleting(undefined);
      },
      onError: (err) =>
        toast.error("Delete failed", {
          description: err instanceof Error ? err.message : "Unknown error",
        }),
    });
  };

  return (
    <div>
      <PageHeader
        title="Source Artifacts"
        description="Source bundles for SAST scans. Upload a ZIP archive of your codebase, then select it when launching a SAST scan."
        actions={
          <Button onClick={() => setUploadOpen(true)} disabled={!projectId}>
            <Upload className="h-4 w-4 mr-1" />
            Upload
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
          message="Failed to load artifacts"
          onRetry={() => refetch()}
        />
      ) : (
        <ArtifactsTable
          artifacts={artifacts ?? []}
          isLoading={isLoading}
          onDelete={(a) => setDeleting(a)}
        />
      )}

      {projectId && (
        <ArtifactUploadDialog
          open={uploadOpen}
          onOpenChange={setUploadOpen}
          projectId={projectId}
        />
      )}

      <Dialog
        open={!!deleting}
        onOpenChange={(v) => !v && setDeleting(undefined)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete source artifact?</DialogTitle>
            <DialogDescription>
              This permanently removes{" "}
              <span className="font-medium text-foreground">
                {deleting?.name}
              </span>{" "}
              and its stored bytes. Scans that referenced it will still show in
              history but will not be re-runnable.
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
