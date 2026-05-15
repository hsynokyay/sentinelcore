"use client";

// Phase-5 governance ops: pending-approvals inbox.
// Surfaces pending governance.approval_requests rows that carry the
// Phase-5 two-person fields and lets a reviewer record a decision via
// the new POST /api/v1/governance/approvals/{id}/decisions endpoint.

import { useMemo, useState } from "react";

import { DataTable, type Column } from "@/components/data/data-table";
import { StatusBadge } from "@/components/badges/status-badge";
import { Button } from "@/components/ui/button";

import { useApprovals } from "./hooks";
import { ApprovalDecisionDialog } from "./approval-decision-dialog";
import type { ApprovalRequest } from "@/lib/types";

function formatRelativeDate(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

interface ApprovalsInboxProps {
  // Optional pre-filter (e.g. only show 'pending').
  status?: string;
}

export function ApprovalsInbox({ status = "pending" }: ApprovalsInboxProps) {
  const { data, isLoading, isError, refetch } = useApprovals({ status, limit: 50 });
  const [selected, setSelected] = useState<ApprovalRequest | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  // Two-person approvals are the new flow — surface those first.
  const requests = useMemo(() => {
    const all = data?.approvals ?? [];
    return [...all].sort((a, b) => {
      const aTwo = (a.required_approvals ?? 1) > 1 ? 0 : 1;
      const bTwo = (b.required_approvals ?? 1) > 1 ? 0 : 1;
      if (aTwo !== bTwo) return aTwo - bTwo;
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });
  }, [data?.approvals]);

  const columns: Column<ApprovalRequest>[] = useMemo(
    () => [
      {
        key: "request_type",
        header: "Type",
        className: "w-[150px]",
        render: (r) => (
          <span className="text-sm font-medium capitalize">
            {r.request_type.replace(/_/g, " ")}
          </span>
        ),
      },
      {
        key: "status",
        header: "Status",
        className: "w-[110px]",
        render: (r) => <StatusBadge status={r.status} />,
      },
      {
        key: "approvals",
        header: "Approvals",
        className: "w-[110px]",
        render: (r) => {
          const required = r.required_approvals ?? 1;
          const current = r.current_approvals ?? 0;
          if (required <= 1) return <span className="text-xs text-muted-foreground">single</span>;
          return (
            <span className="font-mono text-sm tabular-nums">
              {current} / {required}
            </span>
          );
        },
      },
      {
        key: "target",
        header: "Target",
        render: (r) =>
          r.target_transition ? (
            <span className="text-sm">→ {r.target_transition}</span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
      },
      {
        key: "resource",
        header: "Resource",
        render: (r) => (
          <span className="text-sm font-mono text-muted-foreground">
            {r.resource_type}/{r.resource_id.slice(0, 8)}
          </span>
        ),
      },
      {
        key: "created",
        header: "Created",
        className: "w-[100px]",
        render: (r) => (
          <span className="text-sm text-muted-foreground">
            {formatRelativeDate(r.created_at)}
          </span>
        ),
      },
      {
        key: "actions",
        header: "Actions",
        className: "w-[120px]",
        render: (r) =>
          r.status === "pending" ? (
            <Button
              size="xs"
              onClick={(e) => {
                e.stopPropagation();
                setSelected(r);
                setDialogOpen(true);
              }}
            >
              Review
            </Button>
          ) : null,
      },
    ],
    [],
  );

  if (isError) {
    return (
      <div className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">
        Failed to load approvals.{" "}
        <button className="underline" onClick={() => refetch()}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <>
      <DataTable
        columns={columns}
        data={requests}
        isLoading={isLoading}
        emptyMessage="No pending approvals"
      />
      <ApprovalDecisionDialog
        request={selected}
        open={dialogOpen}
        onOpenChange={(o) => {
          setDialogOpen(o);
          if (!o) setSelected(null);
        }}
      />
    </>
  );
}
