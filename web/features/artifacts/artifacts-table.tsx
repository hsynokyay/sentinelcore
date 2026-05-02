"use client";

import { Trash2, FileArchive } from "lucide-react";
import { DataTable, type Column } from "@/components/data/data-table";
import { Button } from "@/components/ui/button";
import type { SourceArtifact } from "@/lib/types";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

function formatRelativeDate(dateStr: string): string {
  const d = new Date(dateStr);
  const diff = Date.now() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

interface ArtifactsTableProps {
  artifacts: SourceArtifact[];
  isLoading?: boolean;
  onDelete: (a: SourceArtifact) => void;
}

export function ArtifactsTable({
  artifacts,
  isLoading,
  onDelete,
}: ArtifactsTableProps) {
  const columns: Column<SourceArtifact>[] = [
    {
      key: "icon",
      header: "",
      className: "w-[40px]",
      render: () => (
        <FileArchive className="h-4 w-4 text-muted-foreground" />
      ),
    },
    {
      key: "name",
      header: "Name",
      render: (a) => (
        <div className="flex flex-col">
          <span className="font-medium">{a.name}</span>
          {a.description && (
            <span className="text-xs text-muted-foreground truncate max-w-[340px]">
              {a.description}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "size",
      header: "Size",
      className: "w-[110px]",
      render: (a) => (
        <span className="text-sm text-muted-foreground">
          {formatBytes(a.size_bytes)}
        </span>
      ),
    },
    {
      key: "entries",
      header: "Files",
      className: "w-[80px]",
      render: (a) => (
        <span className="text-sm text-muted-foreground">{a.entry_count}</span>
      ),
    },
    {
      key: "sha",
      header: "SHA-256",
      className: "w-[120px]",
      render: (a) => (
        <span className="text-xs font-mono text-muted-foreground">
          {a.sha256.slice(0, 12)}…
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Uploaded",
      className: "w-[100px]",
      render: (a) => (
        <span className="text-sm text-muted-foreground">
          {formatRelativeDate(a.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      className: "w-[48px]",
      render: (a) => (
        <Button
          variant="ghost"
          size="icon"
          aria-label="Delete"
          className="text-destructive hover:text-destructive"
          onClick={(e) => {
            e.stopPropagation();
            onDelete(a);
          }}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={artifacts}
      isLoading={isLoading}
      emptyMessage="No source artifacts yet — click Upload to add one."
    />
  );
}
