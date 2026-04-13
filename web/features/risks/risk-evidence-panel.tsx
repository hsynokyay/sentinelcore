"use client";

import {
  ContributionBar,
  type ContributionKind,
} from "@/components/security/contribution-bar";
import {
  intensityNumberWeight,
  severityTextClass,
} from "@/lib/security/intensity";
import type { RiskEvidence, RiskSeverity } from "@/lib/types";

const SCORE_CATEGORIES = new Set([
  "score_base",
  "score_boost",
  "score_penalty",
]);

/** Stagger increment per row — subtle cascade from top to bottom. */
const STAGGER_MS = 80;

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

export interface RiskEvidencePanelProps {
  evidence: RiskEvidence[];
  /** Severity of the parent risk — used to intensity-tint the total row.
   *  When omitted the total renders in default foreground colour. */
  severity?: RiskSeverity;
}

/**
 * RiskEvidencePanel — the explainability surface on the risk detail page.
 *
 * Visualises every scoring contribution as a normalized ContributionBar
 * with category glyphs, staggered mount animation, and proportional
 * fill bars. The largest contribution fills the track; everything else
 * scales relative to it — "look first, read second."
 *
 * Layout:
 *   ┌─────────────────────────────────────────────────┐
 *   │ Why ranked highly?                              │
 *   ├─────────────────────────────────────────────────┤
 *   │ [Layers]   Base score from critical severity +60│
 *   │ ████████████████████████████████████████████████ │
 *   │ [TrendUp]  Confirmed at runtime by DAST    +20  │
 *   │ █████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
 *   │ [TrendUp]  Public exposure                 +15  │
 *   │ ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
 *   ├─────────────────────────────────────────────────┤
 *   │ Total                                      +95  │
 *   ├─────────────────────────────────────────────────┤
 *   │ RELATED                                         │
 *   │ · CWE-601 open_redirect                         │
 *   └─────────────────────────────────────────────────┘
 *
 * The total row sits at the bottom of the scoring section (not in the
 * header) so it reads as the *conclusion* of the bars above it rather
 * than an abstract number. Its font-weight is intensity-aware: higher
 * severity → heavier total, so critical risks have a bolder sum than
 * info risks. The colour is pulled from the severity text class so the
 * total reinforces the severity band visually.
 */
export function RiskEvidencePanel({
  evidence,
  severity,
}: RiskEvidencePanelProps) {
  const sorted = [...evidence].sort((a, b) => a.sort_order - b.sort_order);
  const score = sorted.filter(
    (e) => SCORE_CATEGORIES.has(e.category) && e.weight != null,
  );
  const context = sorted.filter((e) => !SCORE_CATEGORIES.has(e.category));

  // Single pass: compute max |weight| for bar normalization and the
  // running total.
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

  // Intensity-aware emphasis for the total row. Higher severity risks
  // get a heavier total weight so the number feels more urgent.
  // intensityNumberWeight returns "font-bold" / "font-semibold" /
  // "font-medium" based on a 0-4 level. We map severity to a rough
  // intensity: critical=4, high=3, medium=2, low=1, info=0. This
  // doesn't use the full signal model (runtime + exposure) because
  // the evidence panel doesn't have access to those — just severity.
  const severityToIntensity: Record<RiskSeverity, 0 | 1 | 2 | 3 | 4> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const totalWeight = severity
    ? intensityNumberWeight(severityToIntensity[severity])
    : "font-semibold";
  const totalColor = severity ? severityTextClass(severity) : "";

  return (
    <section className="rounded-lg border bg-card p-4">
      <header className="mb-4">
        <h2 className="text-sm font-semibold">Why ranked highly?</h2>
      </header>

      {score.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No score evidence available.
        </p>
      ) : (
        <>
          <ul className="space-y-3">
            {score.map((e, idx) => (
              <li key={`${e.code}-${e.sort_order}`}>
                <ContributionBar
                  label={e.label}
                  weight={e.weight as number}
                  maxAbsWeight={maxAbs}
                  kind={categoryToKind(e.category)}
                  staggerDelay={idx * STAGGER_MS}
                />
              </li>
            ))}
          </ul>

          {/* Total row — sits at the bottom of the scoring section so
              it reads as the conclusion of the bars above, not an
              abstract number in the header. Border-top separates it
              from the contribution list. */}
          <div className="mt-4 flex items-baseline justify-between gap-3 border-t pt-3">
            <span className="text-sm font-medium text-muted-foreground">
              Total
            </span>
            <span
              className={`font-mono tabular-nums text-base ${totalWeight} ${totalColor}`}
            >
              {formattedTotal}
            </span>
          </div>
        </>
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
