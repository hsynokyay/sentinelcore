"use client";

import { Pencil, Trash2, ShieldCheck, ShieldAlert } from "lucide-react";
import { DataTable, type Column } from "@/components/data/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { AuthProfile } from "@/lib/types";

const typeColors: Record<string, string> = {
  bearer_token: "bg-cyan-100 text-cyan-800",
  api_key: "bg-emerald-100 text-emerald-800",
  basic_auth: "bg-amber-100 text-amber-800",
};

const typeLabels: Record<string, string> = {
  bearer_token: "Bearer",
  api_key: "API Key",
  basic_auth: "Basic Auth",
};

interface AuthProfilesTableProps {
  profiles: AuthProfile[];
  isLoading?: boolean;
  onEdit: (p: AuthProfile) => void;
  onDelete: (p: AuthProfile) => void;
}

export function AuthProfilesTable({
  profiles,
  isLoading,
  onEdit,
  onDelete,
}: AuthProfilesTableProps) {
  const columns: Column<AuthProfile>[] = [
    {
      key: "auth_type",
      header: "Type",
      className: "w-[110px]",
      render: (p) => (
        <Badge
          variant="outline"
          className={`text-xs ${typeColors[p.auth_type] || "bg-gray-100 text-gray-700"}`}
        >
          {typeLabels[p.auth_type] || p.auth_type}
        </Badge>
      ),
    },
    {
      key: "name",
      header: "Name",
      render: (p) => (
        <div className="flex flex-col">
          <span className="font-medium">{p.name}</span>
          {p.description && (
            <span className="text-xs text-muted-foreground truncate max-w-[320px]">
              {p.description}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "metadata",
      header: "Details",
      render: (p) => {
        const m = p.metadata || {};
        const parts: string[] = [];
        if (m.header_name) parts.push(`header: ${m.header_name}`);
        if (m.query_name) parts.push(`query: ${m.query_name}`);
        if (m.token_prefix && p.auth_type === "bearer_token")
          parts.push(`prefix: ${m.token_prefix}`);
        if (m.username) parts.push(`user: ${m.username}`);
        if (m.endpoint_url) parts.push(`endpoint: ${m.endpoint_url}`);
        return (
          <span className="text-sm text-muted-foreground font-mono truncate block max-w-[340px]">
            {parts.join(" · ") || "—"}
          </span>
        );
      },
    },
    {
      key: "credentials",
      header: "Credentials",
      className: "w-[150px]",
      render: (p) =>
        p.has_credentials ? (
          <Badge variant="outline" className="bg-emerald-100 text-emerald-800">
            <ShieldCheck className="h-3 w-3 mr-1" />
            Stored (encrypted)
          </Badge>
        ) : (
          <Badge variant="outline" className="bg-red-100 text-red-800">
            <ShieldAlert className="h-3 w-3 mr-1" />
            Missing
          </Badge>
        ),
    },
    {
      key: "actions",
      header: "",
      className: "w-[96px]",
      render: (p) => (
        <div className="flex items-center gap-1 justify-end">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Edit"
            onClick={(e) => {
              e.stopPropagation();
              onEdit(p);
            }}
          >
            <Pencil className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Delete"
            className="text-destructive hover:text-destructive"
            onClick={(e) => {
              e.stopPropagation();
              onDelete(p);
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={profiles}
      isLoading={isLoading}
      emptyMessage="No auth profiles yet — click New Profile to add one."
    />
  );
}
