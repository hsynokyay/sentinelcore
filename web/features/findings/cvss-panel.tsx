"use client";

// CVSSPanel renders the CVSS 3.1 score with a graduated bar and an
// expandable breakdown of every base-metric letter (AV/AC/PR/UI/S/C/I/A).
// Helps triagers reason about *why* the score is what it is instead of
// just seeing a magic number.
interface CVSSPanelProps {
  score: number;
  vector?: string;
}

export function CVSSPanel({ score, vector }: CVSSPanelProps) {
  const band = scoreBand(score);
  const metrics = vector ? parseVector(vector) : null;

  return (
    <div className="rounded-lg border bg-card p-4 flex flex-col gap-3">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          CVSS 3.1
        </span>
        <span className={`text-[10px] font-semibold uppercase tracking-wider ${band.textClass}`}>
          {band.label}
        </span>
      </div>

      <div className="flex items-baseline gap-2">
        <span className={`text-3xl font-semibold tabular-nums ${band.textClass}`}>
          {score.toFixed(1)}
        </span>
        <span className="text-xs text-muted-foreground">/ 10.0</span>
      </div>

      {/* Graduated bar */}
      <div className="relative h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className={`absolute inset-y-0 left-0 ${band.barClass} transition-[width]`}
          style={{ width: `${(score / 10) * 100}%` }}
        />
      </div>

      {metrics && metrics.length > 0 && (
        <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 mt-1 text-[11px]">
          {metrics.map((m) => (
            <div key={m.code} className="flex items-center justify-between gap-2">
              <span className="text-muted-foreground" title={m.metricLabel}>
                {m.metricShort}
              </span>
              <span className="font-medium text-foreground" title={m.valueLabel}>
                {m.valueShort}
              </span>
            </div>
          ))}
        </div>
      )}

      {vector && (
        <code className="text-[10px] font-mono text-muted-foreground break-all bg-muted/40 px-2 py-1.5 rounded border">
          {vector}
        </code>
      )}
    </div>
  );
}

// ---------- helpers ----------

function scoreBand(score: number): {
  label: string;
  textClass: string;
  barClass: string;
} {
  if (score >= 9.0) {
    return {
      label: "Critical",
      textClass: "text-severity-critical",
      barClass: "bg-severity-critical",
    };
  }
  if (score >= 7.0) {
    return {
      label: "High",
      textClass: "text-severity-high",
      barClass: "bg-severity-high",
    };
  }
  if (score >= 4.0) {
    return {
      label: "Medium",
      textClass: "text-severity-medium",
      barClass: "bg-severity-medium",
    };
  }
  if (score > 0) {
    return {
      label: "Low",
      textClass: "text-severity-low",
      barClass: "bg-severity-low",
    };
  }
  return {
    label: "None",
    textClass: "text-muted-foreground",
    barClass: "bg-muted",
  };
}

interface ParsedMetric {
  code: string;
  metricShort: string;
  metricLabel: string;
  valueShort: string;
  valueLabel: string;
}

const METRIC_LABELS: Record<string, { short: string; full: string; values: Record<string, string> }> = {
  AV: {
    short: "Vector",
    full: "Attack Vector",
    values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
  },
  AC: {
    short: "Complexity",
    full: "Attack Complexity",
    values: { L: "Low", H: "High" },
  },
  PR: {
    short: "Priv. Req.",
    full: "Privileges Required",
    values: { N: "None", L: "Low", H: "High" },
  },
  UI: {
    short: "User Int.",
    full: "User Interaction",
    values: { N: "None", R: "Required" },
  },
  S: {
    short: "Scope",
    full: "Scope",
    values: { U: "Unchanged", C: "Changed" },
  },
  C: {
    short: "Confidentiality",
    full: "Confidentiality Impact",
    values: { N: "None", L: "Low", H: "High" },
  },
  I: {
    short: "Integrity",
    full: "Integrity Impact",
    values: { N: "None", L: "Low", H: "High" },
  },
  A: {
    short: "Availability",
    full: "Availability Impact",
    values: { N: "None", L: "Low", H: "High" },
  },
};

const METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

function parseVector(vector: string): ParsedMetric[] {
  // Strip the CVSS:3.x prefix.
  const body = vector.replace(/^CVSS:[0-9.]+\//, "");
  const found = new Map<string, string>();
  for (const part of body.split("/")) {
    const idx = part.indexOf(":");
    if (idx === -1) continue;
    found.set(part.slice(0, idx), part.slice(idx + 1));
  }

  const out: ParsedMetric[] = [];
  for (const code of METRIC_ORDER) {
    const value = found.get(code);
    if (!value) continue;
    const meta = METRIC_LABELS[code];
    if (!meta) continue;
    out.push({
      code,
      metricShort: meta.short,
      metricLabel: meta.full,
      valueShort: value,
      valueLabel: meta.values[value] ?? value,
    });
  }
  return out;
}
