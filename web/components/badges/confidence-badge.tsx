import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const confidenceColors: Record<string, string> = {
  high: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  low: "bg-gray-100 text-gray-600",
};

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  return (
    <Badge variant="outline" className={cn("text-xs", confidenceColors[confidence] || confidenceColors.low)}>
      {confidence}
    </Badge>
  );
}
