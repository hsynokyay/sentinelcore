import type { RiskStatus } from "@/lib/types";

/**
 * Map a risk lifecycle status to the visual state shared by every
 * security primitive (ScoreDisplay, SeverityStrip, etc.).
 *
 * - `active` and `auto_resolved` render as `"active"` because
 *   auto-resolved is transient (auto-reactivates the moment findings
 *   return), so the visual should still feel live.
 * - `user_resolved` renders as `"resolved"` — explicit user action,
 *   earns the desaturated graphics treatment.
 * - `muted` renders as `"muted"` — explicit user action, same
 *   desaturation.
 */
export function lifecycleState(
  status: RiskStatus,
): "active" | "resolved" | "muted" {
  if (status === "user_resolved") return "resolved";
  if (status === "muted") return "muted";
  return "active";
}
