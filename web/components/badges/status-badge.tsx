import { Badge } from "@/components/ui/badge";

// Status-to-tone mapping
// success  → terminal-success states: completed, resolved, approved, mitigated
// error    → terminal-failure states: failed, aborted, rejected
// warning  → caution / recoverable states: reopened, degraded
// info     → in-flight states: new, confirmed, in_progress, running, queued, scheduled
// neutral  → inactive / unknown / risk-accepted states: pending, cancelled, accepted_risk,
//            false_positive, expired, and any unrecognised value
const statusTones: Record<string, "success" | "error" | "warning" | "info" | "neutral"> = {
  // Vulnerability / finding statuses
  new: "info",
  confirmed: "info",
  in_progress: "info",
  mitigated: "success",
  resolved: "success",
  reopened: "warning",
  accepted_risk: "neutral",
  false_positive: "neutral",
  // Scan statuses
  queued: "info",
  running: "info",
  completed: "success",
  failed: "error",
  cancelled: "neutral",
  aborted: "error",
  // Approval statuses
  pending: "neutral",
  approved: "success",
  rejected: "error",
  expired: "neutral",
};

export function StatusBadge({ status }: { status: string }) {
  const label = status.replace(/_/g, " ");
  const tone = statusTones[status] ?? "neutral";

  return (
    <Badge variant="status" tone={tone} className="text-xs capitalize">
      {label}
    </Badge>
  );
}
