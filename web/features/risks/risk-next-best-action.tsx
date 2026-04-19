"use client";

import {
  NextBestAction,
  type NextBestActionDetail,
} from "@/components/security/next-best-action";
import {
  intensityFromSignals,
  intensityToActionTitle,
} from "@/lib/security/intensity";
import { isRuntimeConfirmed } from "@/lib/security/runtime";
import type { RiskClusterDetail } from "@/lib/types";

// ─── Reasons ────────────────────────────────────────────────────────

const SEVERITY_LABELS: Record<RiskClusterDetail["severity"], string> = {
  critical: "Critical severity",
  high: "High severity",
  medium: "Medium severity",
  low: "Low severity",
  info: "Informational",
};

function buildReasons(risk: RiskClusterDetail): string[] {
  const out: string[] = [SEVERITY_LABELS[risk.severity]];
  if (isRuntimeConfirmed(risk)) out.push("Confirmed at runtime");
  if (risk.exposure === "public" || risk.exposure === "both")
    out.push("Public exposure");
  if (risk.finding_count > 1)
    out.push(`${risk.finding_count} linked findings`);
  return out.slice(0, 4);
}

// ─── Score reduction estimate ───────────────────────────────────────

/**
 * Compute the expected score reduction from addressing the *removable*
 * signals. Base severity is not removable (the vuln class doesn't
 * change), but boosts like runtime confirmation and public exposure
 * go away when the underlying finding is fixed or the endpoint is
 * restricted.
 *
 * Strategy: sum the positive-weight evidence entries whose category
 * is `score_boost`. That's the maximum reduction achievable by fixing
 * the findings that contributed those boosts. If there are no boosts,
 * the reduction is the base score itself (fixing the last finding
 * closes the cluster entirely).
 */
function computeScoreReduction(risk: RiskClusterDetail): number {
  const boosts = risk.evidence.filter(
    (e) => e.category === "score_boost" && e.weight != null && e.weight > 0,
  );
  if (boosts.length > 0) {
    return boosts.reduce((sum, e) => sum + (e.weight ?? 0), 0);
  }
  // No boosts — fixing the remaining findings closes the cluster entirely.
  return risk.risk_score;
}

// ─── Effort estimate ────────────────────────────────────────────────

/**
 * Heuristic effort estimate based on vuln class complexity and finding
 * count. The estimate is intentionally coarse — "Low", "Low–Medium",
 * "Medium", "Medium–High", "High" — because anything finer would be
 * false precision without knowing the specific codebase.
 *
 * Factors:
 *  - High-complexity classes (injection, deserialization, ssrf) start
 *    at Medium and scale up with finding count.
 *  - Medium-complexity classes (xss, open_redirect, path_traversal)
 *    start at Low–Medium.
 *  - Everything else (info disclosure, misconfig) starts at Low.
 *  - Multiple findings in the cluster bump the estimate one tier.
 */
const HIGH_COMPLEXITY = new Set([
  "sql_injection",
  "command_injection",
  "unsafe_deserialization",
  "ssrf",
  "code_injection",
]);

const MEDIUM_COMPLEXITY = new Set([
  "xss",
  "open_redirect",
  "path_traversal",
  "sensitive_logging",
]);

function estimateEffort(risk: RiskClusterDetail): string {
  const cls = risk.vuln_class.toLowerCase();
  const multi = risk.finding_count > 2;

  if (HIGH_COMPLEXITY.has(cls)) {
    return multi ? "High" : "Medium–High";
  }
  if (MEDIUM_COMPLEXITY.has(cls)) {
    return multi ? "Medium" : "Low–Medium";
  }
  return multi ? "Low–Medium" : "Low";
}

// ─── Verification guidance ──────────────────────────────────────────

/**
 * Short guidance text on how to verify the fix was effective. Derived
 * from the risk's fingerprint kind (DAST route vs SAST file) since
 * the verification method differs fundamentally between them.
 */
function verificationGuidance(risk: RiskClusterDetail): string {
  if (risk.fingerprint_kind === "dast_route") {
    return `Re-scan ${risk.http_method ?? "the"} ${risk.canonical_route ?? "endpoint"} — the runtime signal should disappear.`;
  }
  return `Re-run SAST on ${risk.file_path ?? "the affected file"} — the finding should no longer appear.`;
}

// ─── Details builder ────────────────────────────────────────────────

function buildDetails(risk: RiskClusterDetail): NextBestActionDetail[] {
  const details: NextBestActionDetail[] = [];

  // Score reduction
  const reduction = computeScoreReduction(risk);
  if (reduction > 0) {
    const qualifier = reduction >= risk.risk_score ? "up to" : "≈";
    details.push({
      label: "Expected reduction",
      value:
        reduction >= risk.risk_score
          ? `${qualifier} ${reduction} pts (closes the cluster)`
          : `${qualifier} −${reduction} pts`,
    });
  }

  // Effort
  details.push({
    label: "Estimated effort",
    value: estimateEffort(risk),
  });

  // Verification
  details.push({
    label: "Verify",
    value: verificationGuidance(risk),
  });

  return details;
}

// ─── Component ──────────────────────────────────────────────────────

/**
 * RiskNextBestAction — risk-aware wrapper around the generic
 * NextBestAction primitive. Derives urgency, reasons, score reduction,
 * effort estimate, verification guidance, and CTAs from a
 * RiskClusterDetail.
 *
 * Lifecycle gating: returns `null` for `user_resolved` and `muted`.
 *
 * Fallback handling: when evidence is empty or findings are missing,
 * the panel still renders with whatever data is available. Score
 * reduction falls back to the full risk_score (closing the cluster).
 * CTA is omitted only when there are zero linked findings. Effort
 * and verification guidance always have a value.
 */
export function RiskNextBestAction({ risk }: { risk: RiskClusterDetail }) {
  if (risk.status === "user_resolved" || risk.status === "muted") {
    return null;
  }

  const intensity = intensityFromSignals({
    severity: risk.severity,
    runtimeConfirmed: isRuntimeConfirmed(risk),
    publicExposure: risk.exposure === "public" || risk.exposure === "both",
  });

  const title = intensityToActionTitle(intensity);
  const reasons = buildReasons(risk);
  const details = buildDetails(risk);

  const firstFinding = risk.findings[0];
  const primaryAction = firstFinding
    ? {
        label: "Open first finding",
        href: `/findings/${firstFinding.id}`,
      }
    : undefined;

  // Secondary CTA: "Accept risk" navigates nowhere — it's a conceptual
  // placeholder for a future risk-acceptance workflow. For now, omit it
  // so we don't have a dead button.
  return (
    <NextBestAction
      severity={risk.severity}
      intensity={intensity}
      title={title}
      reasons={reasons}
      details={details}
      primaryAction={primaryAction}
    />
  );
}
