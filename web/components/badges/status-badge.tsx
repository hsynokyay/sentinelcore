import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const statusColors: Record<string, string> = {
  new: "bg-blue-100 text-blue-800",
  confirmed: "bg-purple-100 text-purple-800",
  in_progress: "bg-yellow-100 text-yellow-800",
  mitigated: "bg-emerald-100 text-emerald-800",
  resolved: "bg-green-100 text-green-800",
  reopened: "bg-orange-100 text-orange-800",
  accepted_risk: "bg-slate-100 text-slate-800",
  false_positive: "bg-gray-100 text-gray-600",
  // Scan statuses
  queued: "bg-slate-100 text-slate-700",
  running: "bg-blue-100 text-blue-700",
  completed: "bg-green-100 text-green-700",
  failed: "bg-red-100 text-red-700",
  cancelled: "bg-gray-100 text-gray-600",
  aborted: "bg-red-100 text-red-600",
  // Approval statuses
  pending: "bg-yellow-100 text-yellow-800",
  approved: "bg-green-100 text-green-800",
  rejected: "bg-red-100 text-red-800",
  expired: "bg-gray-100 text-gray-600",
};

export function StatusBadge({ status }: { status: string }) {
  const label = status.replace(/_/g, " ");
  return (
    <Badge variant="outline" className={cn("text-xs capitalize", statusColors[status] || "bg-gray-100 text-gray-700")}>
      {label}
    </Badge>
  );
}
