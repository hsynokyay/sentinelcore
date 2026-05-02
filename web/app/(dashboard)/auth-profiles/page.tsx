"use client";

import { useState, useMemo } from "react";
import { Plus, KeyRound } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/data/page-header";
import { DensityToggle } from "@/components/data/density-toggle";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
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
  useAuthProfiles,
  useDeleteAuthProfile,
} from "@/features/auth-profiles/hooks";
import { AuthProfilesTable } from "@/features/auth-profiles/auth-profiles-table";
import { AuthProfileFormDialog } from "@/features/auth-profiles/auth-profile-form-dialog";
import type { AuthProfile } from "@/lib/types";

export default function AuthProfilesPage() {
  const { data: projectsData, isLoading: loadingProjects } = useProjects();
  const projects = useMemo(() => projectsData?.projects ?? [], [projectsData]);
  const [projectId, setProjectId] = useState<string>("");

  if (!projectId && projects.length > 0) {
    setProjectId(projects[0].id);
  }

  const {
    data: profiles,
    isLoading,
    isError,
    refetch,
  } = useAuthProfiles(projectId || undefined);
  const deleteMut = useDeleteAuthProfile(projectId || undefined);

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<AuthProfile | undefined>(undefined);
  const [deleting, setDeleting] = useState<AuthProfile | undefined>(undefined);

  const openCreate = () => {
    setEditing(undefined);
    setFormOpen(true);
  };
  const openEdit = (p: AuthProfile) => {
    setEditing(p);
    setFormOpen(true);
  };
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

  const profileList = profiles ?? [];
  const isEmpty = !isLoading && profileList.length === 0;

  return (
    <>
      <PageHeader
        title="Auth Profiles"
        description="DAST credentials — bearer tokens, API keys, and basic auth. Secrets are encrypted at rest and never returned."
        count={isLoading ? "—" : profileList.length}
        filters={
          <Select
            value={projectId}
            onValueChange={setProjectId}
            disabled={loadingProjects}
            itemToStringLabel={(v) => {
              const p = projects.find((p) => p.id === v);
              return p ? (p.display_name || p.name) : "";
            }}
          >
            <SelectTrigger className="w-48">
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
        }
        actions={
          <>
            <DensityToggle />
            <Button onClick={openCreate} disabled={!projectId}>
              <Plus className="h-4 w-4 mr-1" />
              New Profile
            </Button>
          </>
        }
      />

      {isError ? (
        <ErrorState
          message="Failed to load auth profiles"
          onRetry={() => refetch()}
        />
      ) : isEmpty ? (
        <EmptyStateBranded
          icon={KeyRound}
          title="No auth profiles"
          description="Add bearer tokens, API keys, or basic auth credentials for authenticated DAST scans."
          action={{ label: "New profile", onClick: openCreate }}
        />
      ) : (
        <AuthProfilesTable
          profiles={profileList}
          isLoading={isLoading}
          onEdit={openEdit}
          onDelete={(p) => setDeleting(p)}
        />
      )}

      {projectId && (
        <AuthProfileFormDialog
          open={formOpen}
          onOpenChange={setFormOpen}
          projectId={projectId}
          existing={editing}
        />
      )}

      <Dialog
        open={!!deleting}
        onOpenChange={(v) => !v && setDeleting(undefined)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete auth profile?</DialogTitle>
            <DialogDescription>
              This permanently removes{" "}
              <span className="font-medium text-foreground">
                {deleting?.name}
              </span>{" "}
              and its stored credentials. Targets referencing this profile will
              be detached.
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
    </>
  );
}
