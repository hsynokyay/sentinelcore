"use client";

// Phase-5 governance ops: per-approver decision dialog.
// Renders the two-person rule progress indicator and posts to the new
// /api/v1/governance/approvals/{id}/decisions endpoint via
// useSubmitApprovalDecision().

import { useEffect, useState } from "react";
import { CheckCircle2, Loader2, ShieldCheck, XCircle } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import { useSubmitApprovalDecision } from "./hooks";
import type { ApprovalRequest } from "@/lib/types";

interface ApprovalDecisionDialogProps {
  request: ApprovalRequest | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ApprovalDecisionDialog({ request, open, onOpenChange }: ApprovalDecisionDialogProps) {
  const submit = useSubmitApprovalDecision();
  const [reason, setReason] = useState("");
  const [decision, setDecision] = useState<"approve" | "reject">("approve");

  // Reset local state whenever a different request opens.
  useEffect(() => {
    if (!open) return;
    setReason("");
    setDecision("approve");
    submit.reset();
  }, [open, request?.id, submit]);

  if (!request) return null;

  const required = request.required_approvals ?? 1;
  const current = request.current_approvals ?? 0;
  const remaining = Math.max(required - current, 0);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reason.trim()) return;
    submit.mutate(
      { id: request.id, decision, reason: reason.trim() },
      {
        onSuccess: (updated) => {
          if (updated.status === "executed" || updated.status === "approved") {
            toast.success(
              decision === "approve"
                ? "Approval recorded — transition executed"
                : "Decision recorded",
            );
          } else if (updated.status === "rejected") {
            toast.success("Approval rejected");
          } else {
            toast.success(`Approval recorded (${current + 1}/${required})`);
          }
          onOpenChange(false);
        },
        onError: (err) => {
          toast.error("Failed to submit decision", {
            description: err instanceof Error ? err.message : "Unknown error",
          });
        },
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            Review approval request
          </DialogTitle>
          <DialogDescription>
            {request.request_type.replace(/_/g, " ")} for {request.resource_type}{" "}
            <code className="text-xs">{request.resource_id.slice(0, 8)}</code>
            {request.target_transition ? (
              <>
                {" "}
                → <strong>{request.target_transition}</strong>
              </>
            ) : null}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 text-sm">
          {/* Two-person progress meter */}
          <div className="rounded-md border px-3 py-2">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Approvals</span>
              <span className="font-mono">
                {current} / {required}
              </span>
            </div>
            {remaining > 0 ? (
              <p className="text-xs text-muted-foreground mt-1">
                {remaining} more {remaining === 1 ? "approver" : "approvers"} required
                before the transition fires.
              </p>
            ) : (
              <p className="text-xs text-muted-foreground mt-1">
                Threshold met; the next approval will execute the transition.
              </p>
            )}
          </div>

          <div className="space-y-1">
            <Label>Requester</Label>
            <p className="text-xs text-muted-foreground font-mono">{request.requested_by}</p>
          </div>

          <div className="space-y-1">
            <Label>Reason from requester</Label>
            <p className="text-xs whitespace-pre-wrap">{request.reason}</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="approval-decision-reason">
              Your reason
              <span className="text-destructive"> *</span>
            </Label>
            <Textarea
              id="approval-decision-reason"
              placeholder="Why are you approving or rejecting this request?"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              required
            />
          </div>

          {submit.isError && (
            <p className="text-sm text-destructive">
              {submit.error instanceof Error ? submit.error.message : "Submission failed"}
            </p>
          )}

          <DialogFooter className="flex-col sm:flex-row gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={submit.isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="destructive"
              onClick={() => setDecision("reject")}
              disabled={submit.isPending || !reason.trim()}
            >
              {submit.isPending && decision === "reject" ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <XCircle className="h-4 w-4 mr-1" />
              )}
              Reject
            </Button>
            <Button
              type="submit"
              onClick={() => setDecision("approve")}
              disabled={submit.isPending || !reason.trim()}
            >
              {submit.isPending && decision === "approve" ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <CheckCircle2 className="h-4 w-4 mr-1" />
              )}
              Approve
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
