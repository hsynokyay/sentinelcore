"use client";

import { useState } from "react";
import { DataTable, type Column } from "@/components/data/data-table";
import { StatusBadge } from "@/components/badges/status-badge";
import { Button } from "@/components/ui/button";
import { useDecideApproval } from "./hooks";
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

function ApprovalActions({ request }: { request: ApprovalRequest }) {
  const decide = useDecideApproval();
  const [reason, setReason] = useState("");
  const [showReason, setShowReason] = useState(false);
  const [pendingDecision, setPendingDecision] = useState<"approved" | "rejected" | null>(null);

  if (request.status !== "pending") return null;

  if (showReason) {
    return (
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason..."
          className="border rounded px-2 py-1 text-xs w-32 bg-background"
          onClick={(e) => e.stopPropagation()}
        />
        <Button
          size="xs"
          onClick={(e) => {
            e.stopPropagation();
            if (pendingDecision && reason.trim()) {
              decide.mutate({ id: request.id, decision: pendingDecision, reason });
              setShowReason(false);
            }
          }}
          disabled={!reason.trim() || decide.isPending}
        >
          Confirm
        </Button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-1">
      <Button
        size="xs"
        onClick={(e) => {
          e.stopPropagation();
          setPendingDecision("approved");
          setShowReason(true);
        }}
      >
        Approve
      </Button>
      <Button
        size="xs"
        variant="destructive"
        onClick={(e) => {
          e.stopPropagation();
          setPendingDecision("rejected");
          setShowReason(true);
        }}
      >
        Reject
      </Button>
    </div>
  );
}

const columns: Column<ApprovalRequest>[] = [
  {
    key: "request_type",
    header: "Type",
    className: "w-[140px]",
    render: (r) => (
      <span className="text-sm font-medium capitalize">{r.request_type.replace(/_/g, " ")}</span>
    ),
  },
  {
    key: "status",
    header: "Status",
    className: "w-[110px]",
    render: (r) => <StatusBadge status={r.status} />,
  },
  {
    key: "requester",
    header: "Requester",
    render: (r) => (
      <span className="text-sm text-muted-foreground">{r.requested_by}</span>
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
      <span className="text-sm text-muted-foreground">{formatRelativeDate(r.created_at)}</span>
    ),
  },
  {
    key: "actions",
    header: "Actions",
    className: "w-[200px]",
    render: (r) => <ApprovalActions request={r} />,
  },
];

interface ApprovalsTableProps {
  requests: ApprovalRequest[];
  isLoading?: boolean;
}

export function ApprovalsTable({ requests, isLoading }: ApprovalsTableProps) {
  return (
    <DataTable
      columns={columns}
      data={requests}
      isLoading={isLoading}
      emptyMessage="No approval requests"
    />
  );
}
