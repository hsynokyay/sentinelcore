import { Badge } from "@/components/ui/badge";

export function SeverityBadge({ severity }: { severity: string }) {
  const tone = (["critical", "high", "medium", "low", "info"].includes(severity)
    ? severity
    : "info") as "critical" | "high" | "medium" | "low" | "info";

  return (
    <Badge variant="severity" tone={tone} className="text-xs font-semibold uppercase">
      {severity}
    </Badge>
  );
}
