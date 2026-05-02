import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const severityColors: Record<string, string> = {
  critical: "bg-red-600 text-white hover:bg-red-700",
  high: "bg-orange-500 text-white hover:bg-orange-600",
  medium: "bg-yellow-500 text-black hover:bg-yellow-600",
  low: "bg-blue-500 text-white hover:bg-blue-600",
  info: "bg-slate-400 text-white hover:bg-slate-500",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge className={cn("text-xs font-semibold uppercase", severityColors[severity] || severityColors.info)}>
      {severity}
    </Badge>
  );
}
