"use client";

import {
  ContributionBar,
  type ContributionKind,
} from "@/components/security/contribution-bar";
import type { RiskEvidence } from "@/lib/types";

const SCORE_CATEGORIES = new Set([
  "score_base",
  "score_boost",
  "score_penalty",
]);

/**
 * Map a RiskEvidence.category enum onto a ContributionBar kind. Only
 * scoring categories make it into the breakdown — link / context / unknown
 * categories drop into the "Related" footer.
 */
function categoryToKind(category: string): ContributionKind {
  if (category === "score_boost") return "boost";
  if (category === "score_penalty") return "penalty";
  return "base";
}

/**
 * RiskEvidencePanel — the explainability surface on the risk detail page.
 *
 * Visualises every scoring contribution as a normalized ContributionBar so
 * the user can compare boost / penalty / base magnitudes at a glance,
 * without reading the numbers. The largest contribution renders at 100%
 * width and everything else scales relative to it; this preserves the
 * "look first, read second" reading order the playbook calls for.
 *
 * The header carries a running total (= sum of signed contributions),
 * which on every observed risk equals risk_score because every score
 * component is captured as evidence — but we don't promise that contract
 * here, we just show the math.
 *
 * Non-scoring evidence (link / context) drops into a small "Related"
 * footer below the breakdown — same UX as the previous version, just
 * without the colour bug where penalties rendered green.
 */
export function RiskEvidencePanel({ evidence }: { evidence: RiskEvidence[] }) {
  const sorted = [...evidence].sort((a, b) => a.sort_order - b.sort_order);
  const score = sorted.filter(
    (e) => SCORE_CATEGORIES.has(e.category) && e.weight != null,
  );
  const context = sorted.filter((e) => !SCORE_CATEGORIES.has(e.category));

  // Single pass over the score evidence: compute the max |weight| for
  // bar normalization and the running total in the same loop.
  const { maxAbs, total } = score.reduce(
    (acc, e) => {
      const w = e.weight as number;
      return {
        maxAbs: Math.max(acc.maxAbs, Math.abs(w)),
        total: acc.total + w,
      };
    },
    { maxAbs: 0, total: 0 },
  );

  const formattedTotal = total >= 0 ? `+${total}` : `${total}`;

  return (
    <section className="rounded-lg border bg-card p-4">
      <header className="mb-4 flex items-baseline justify-between gap-3">
        <h2 className="text-sm font-semibold">Why ranked highly?</h2>
        {score.length > 0 && (
          <span className="font-mono tabular-nums text-xs text-muted-foreground">
            total{" "}
            <span className="ml-1 text-sm font-semibold text-foreground">
              {formattedTotal}
            </span>
          </span>
        )}
      </header>

      {score.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No score evidence available.
        </p>
      ) : (
        <ul className="space-y-3">
          {score.map((e) => (
            <li key={`${e.code}-${e.sort_order}`}>
              <ContributionBar
                label={e.label}
                weight={e.weight as number}
                maxAbsWeight={maxAbs}
                kind={categoryToKind(e.category)}
              />
            </li>
          ))}
        </ul>
      )}

      {context.length > 0 && (
        <div className="mt-5 border-t pt-3">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Related
          </h3>
          <ul className="space-y-1">
            {context.map((e) => (
              <li
                key={`ctx-${e.code}-${e.sort_order}`}
                className="text-xs text-muted-foreground"
              >
                {e.label}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
