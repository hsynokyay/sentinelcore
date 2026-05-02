"use client";

import { useState } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
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

import { useActivateEmergencyStop } from "./hooks";

interface EmergencyStopDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function EmergencyStopDialog({ open, onOpenChange }: EmergencyStopDialogProps) {
  const [scope, setScope] = useState("all");
  const [reason, setReason] = useState("");
  const activate = useActivateEmergencyStop();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!reason.trim()) return;

    activate.mutate(
      { scope, reason: reason.trim() },
      {
        onSuccess: () => {
          toast.success("Emergency stop activated");
          onOpenChange(false);
          setScope("all");
          setReason("");
          activate.reset();
        },
        onError: (error) => {
          toast.error("Failed to activate emergency stop", {
            description: error instanceof Error ? error.message : "Unknown error",
          });
        },
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o);
        if (!o) {
          setScope("all");
          setReason("");
          activate.reset();
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="h-5 w-5" />
            Activate Emergency Stop
          </DialogTitle>
          <DialogDescription>
            This will immediately halt all scanning activity within the selected scope.
            A second operator is required to lift the stop (four-eyes principle).
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Scope */}
          <div className="space-y-1.5">
            <Label>Scope</Label>
            <Select value={scope} onValueChange={setScope}>
              <SelectTrigger>
                <SelectValue placeholder="Select scope" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All (Organization-wide)</SelectItem>
                <SelectItem value="team">Team</SelectItem>
                <SelectItem value="project">Project</SelectItem>
                <SelectItem value="scan_job">Scan Job</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Reason */}
          <div className="space-y-1.5">
            <Label>Reason</Label>
            <Textarea
              placeholder="Describe why the emergency stop is needed..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              required
            />
            {reason.trim().length === 0 && (
              <p className="text-xs text-muted-foreground">A reason is required.</p>
            )}
          </div>

          {/* Error */}
          {activate.isError && (
            <p className="text-sm text-destructive">
              {activate.error instanceof Error ? activate.error.message : "Failed to activate"}
            </p>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant="destructive"
              disabled={activate.isPending || !reason.trim()}
            >
              {activate.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1" />}
              {activate.isPending ? "Activating..." : "Activate Emergency Stop"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
