"use client";

import { NextBestAction } from "@/components/security/next-best-action";
import {
  intensityFromSignals,
  intensityToActionTitle,
} from "@/lib/security/intensity";
import type { RiskClusterDetail } from "@/lib/types";

/**
 * Detect whether a risk has been runtime-confirmed by inspecting two
 * sources, in order of trust:
 *
 *  1. `relations` — a typed enum field. If any related cluster has the
 *     `runtime_confirmation` relation type, that's the strongest signal.
 *  2. `evidence` — fallback for risks where the relation hasn't been
 *     materialised yet but the score evidence already mentions runtime.
 *     We do a case-insensitive substring on label *and* code so the
 *     check survives small wording changes upstream.
 */
function isRuntimeConfirmed(risk: RiskClusterDetail): boolean {
  if (
    risk.relations.some((rel) => rel.relation_type === "runtime_confirmation")
  ) {
    return true;
  }
  return risk.evidence.some((e) => {
    const haystack = `${e.code} ${e.label}`.toLowerCase();
    return haystack.includes("runtime");
  });
}

/**
 * Friendly severity label for the reasons list. Title-case so it reads
 * naturally in a sentence-like context ("Critical severity · Public
 * exposure · Confirmed at runtime").
 */
const SEVERITY_LABELS: Record<RiskClusterDetail["severity"], string> = {
  critical: "Critical severity",
  high: "High severity",
  medium: "Medium severity",
  low: "Low severity",
  info: "Informational",
};

/**
 * Build the ordered list of reasons that justify the recommended action.
 * The order matters: severity is always first (it sets the floor), then
 * the two strongest escalation signals (runtime, public), then secondary
 * context (cluster size). We cap at four entries so the chip row stays
 * readable on a single line at typical viewport widths.
 */
function buildReasons(risk: RiskClusterDetail): string[] {
  const out: string[] = [SEVERITY_LABELS[risk.severity]];

  if (isRuntimeConfirmed(risk)) {
    out.push("Confirmed at runtime");
  }
  if (risk.exposure === "public" || risk.exposure === "both") {
    out.push("Public exposure");
  }
  if (risk.finding_count > 1) {
    out.push(`${risk.finding_count} linked findings`);
  }

  return out.slice(0, 4);
}

/**
 * RiskNextBestAction — risk-aware wrapper around the generic
 * NextBestAction primitive. Derives the urgency, reasons, and primary
 * CTA from a RiskClusterDetail and renders the panel.
 *
 * Lifecycle gating: returns `null` for `user_resolved` and `muted`. The
 * panel answers "what to do RIGHT NOW", which makes no sense on a
 * closed risk and would just add visual noise. Active and the transient
 * `auto_resolved` (which auto-reactivates the moment findings return)
 * both render normally.
 *
 * The primary CTA is "Open first finding" — almost always the right
 * starting point, since the rule guidance and the remediation pack live
 * on the finding row, not the cluster. If the cluster has zero linked
 * findings (an edge case where the cluster exists but its members have
 * been merged elsewhere), the CTA is omitted.
 */
export function RiskNextBestAction({ risk }: { risk: RiskClusterDetail }) {
  // Lifecycle gate. Closed risks don't get an action panel.
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

  const firstFinding = risk.findings[0];
  const primaryAction = firstFinding
    ? {
        label: "Open first finding",
        href: `/findings/${firstFinding.id}`,
      }
    : undefined;

  return (
    <NextBestAction
      severity={risk.severity}
      intensity={intensity}
      title={title}
      reasons={reasons}
      primaryAction={primaryAction}
    />
  );
}
