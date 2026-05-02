import type { RiskCluster, RiskClusterDetail, RiskRelation } from "@/lib/types";

/**
 * Detect whether a risk has been runtime-confirmed. Checks two
 * sources in order of trust:
 *
 *  1. `relations` — a typed enum field. If any related cluster has
 *     the `runtime_confirmation` relation type, that's the strongest
 *     signal. Only available on `RiskClusterDetail` (the full detail
 *     payload), not on `RiskCluster` (the list row).
 *
 *  2. `top_reasons` / evidence — fallback for list rows and for
 *     risks where the relation hasn't been materialised yet. A
 *     case-insensitive substring check on code + label survives
 *     small wording changes upstream.
 *
 * This function is intentionally polymorphic: it accepts both the
 * list-row shape (`RiskCluster`, which has `top_reasons`) and the
 * detail shape (`RiskClusterDetail`, which also has `relations` and
 * `evidence`). The caller doesn't need to know which shape they have.
 */
export function isRuntimeConfirmed(
  risk: RiskCluster | RiskClusterDetail,
): boolean {
  // 1. Check typed relations (detail-only field).
  if ("relations" in risk) {
    const relations = (risk as RiskClusterDetail).relations as RiskRelation[];
    if (relations.some((rel) => rel.relation_type === "runtime_confirmation")) {
      return true;
    }
  }

  // 2. Check evidence labels (detail-only field).
  if ("evidence" in risk) {
    const evidence = (risk as RiskClusterDetail).evidence;
    if (
      evidence.some((e) => {
        const haystack = `${e.code} ${e.label}`.toLowerCase();
        return haystack.includes("runtime");
      })
    ) {
      return true;
    }
  }

  // 3. Check top_reasons (available on both list and detail shapes).
  if (risk.top_reasons) {
    return risk.top_reasons.some(
      (r) =>
        r.code?.toLowerCase().includes("runtime") ||
        r.label?.toLowerCase().includes("runtime"),
    );
  }

  return false;
}
