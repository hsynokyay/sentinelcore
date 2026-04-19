"use client";

import { useState, useRef } from "react";
import { Loader2, Upload } from "lucide-react";
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

import { useUploadSourceArtifact } from "./hooks";

const MAX_BYTES = 256 * 1024 * 1024; // 256 MiB, matches backend DefaultLimits.

interface ArtifactUploadDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
}

export function ArtifactUploadDialog({
  open,
  onOpenChange,
  projectId,
}: ArtifactUploadDialogProps) {
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [progress, setProgress] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const uploadMut = useUploadSourceArtifact(projectId);

  const reset = () => {
    setFile(null);
    setName("");
    setDescription("");
    setProgress(0);
    setError(null);
    if (fileRef.current) fileRef.current.value = "";
  };

  const close = () => {
    reset();
    onOpenChange(false);
  };

  const submit = () => {
    setError(null);
    if (!file) {
      setError("Select a ZIP file");
      return;
    }
    if (file.size > MAX_BYTES) {
      setError(`File exceeds ${Math.floor(MAX_BYTES / 1024 / 1024)} MiB limit`);
      return;
    }
    if (!/\.zip$/i.test(file.name)) {
      setError("Only .zip archives are accepted");
      return;
    }

    uploadMut.mutate(
      {
        file,
        name: name || undefined,
        description: description || undefined,
        onProgress: ({ loaded, total }) =>
          setProgress(Math.floor((loaded / total) * 100)),
      },
      {
        onSuccess: (artifact) => {
          toast.success(`Uploaded ${artifact.name}`, {
            description: `${artifact.entry_count} files, ${formatBytes(artifact.size_bytes)}`,
          });
          close();
        },
        onError: (err) => {
          const msg = err instanceof Error ? err.message : "Unknown error";
          setError(msg);
          toast.error("Upload failed", { description: msg });
        },
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={(v) => (v ? onOpenChange(true) : close())}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Upload Source Artifact</DialogTitle>
          <DialogDescription>
            Upload a source bundle (ZIP) for SAST scanning. Archive contents
            are validated for safety before storage — symlinks, absolute paths,
            and parent traversal are rejected.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>ZIP File</Label>
            <Input
              ref={fileRef}
              type="file"
              accept=".zip,application/zip"
              onChange={(e) => {
                const f = e.target.files?.[0] ?? null;
                setFile(f);
                if (f && !name) setName(f.name.replace(/\.zip$/i, ""));
              }}
            />
            {file && (
              <p className="text-xs text-muted-foreground">
                {file.name} · {formatBytes(file.size)}
              </p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label>
              Name{" "}
              <span className="text-muted-foreground font-normal">
                (optional)
              </span>
            </Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="my-app-v1.2"
            />
          </div>

          <div className="space-y-1.5">
            <Label>
              Description{" "}
              <span className="text-muted-foreground font-normal">
                (optional)
              </span>
            </Label>
            <Textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          {uploadMut.isPending && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>Uploading…</span>
                <span>{progress}%</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={close}
            disabled={uploadMut.isPending}
          >
            Cancel
          </Button>
          <Button onClick={submit} disabled={uploadMut.isPending || !file}>
            {uploadMut.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <Upload className="h-4 w-4 mr-1" />
            )}
            Upload
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}
