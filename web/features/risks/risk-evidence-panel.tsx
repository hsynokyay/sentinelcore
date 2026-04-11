"use client";

import type { RiskEvidence } from "@/lib/types";

const categoryStyles: Record<string, string> = {
  score_base: "text-foreground font-semibold",
  score_boost: "text-emerald-700",
  score_penalty: "text-red-700",
  link: "text-muted-foreground",
  context: "text-muted-foreground",
};

function formatWeight(w: number | null): string {
  if (w == null) return "";
  if (w >= 0) return `+${w}`;
  return String(w);
}

export function RiskEvidencePanel({ evidence }: { evidence: RiskEvidence[] }) {
  const sorted = [...evidence].sort((a, b) => a.sort_order - b.sort_order);
  const score = sorted.filter((e) =>
    ["score_base", "score_boost", "score_penalty"].includes(e.category),
  );
  const context = sorted.filter(
    (e) => !["score_base", "score_boost", "score_penalty"].includes(e.category),
  );
  return (
    <section className="rounded-lg border bg-card p-4">
      <h2 className="mb-3 text-sm font-semibold">Why ranked highly?</h2>
      <ul className="space-y-2">
        {score.map((e) => (
          <li
            key={`${e.code}-${e.sort_order}`}
            className="flex items-start justify-between gap-3"
          >
            <span className={categoryStyles[e.category] ?? "text-foreground"}>
              {e.label}
            </span>
            {e.weight != null && (
              <span
                className={`font-mono text-sm tabular-nums ${
                  e.category === "score_base" ? "text-foreground" : "text-emerald-700"
                }`}
              >
                {formatWeight(e.weight)}
              </span>
            )}
          </li>
        ))}
        {score.length === 0 && (
          <li className="text-xs text-muted-foreground">
            No score evidence available.
          </li>
        )}
      </ul>
      {context.length > 0 && (
        <div className="mt-4 border-t pt-3">
          <h3 className="mb-2 text-xs font-semibold uppercase text-muted-foreground">
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
