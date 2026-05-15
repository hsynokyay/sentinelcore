"use client";

import { ExternalLink } from "lucide-react";

interface ClassificationPanelProps {
  cweId?: number;
  owaspCategory?: string;
  riskScore?: number;
  confidence?: string;
  ruleId?: string;
}

// ClassificationPanel renders the rule's taxonomy classifications side-by-
// side. CWE links to MITRE; OWASP links to the official Top 10 page.
// Both are click-through so a triager can reach authoritative docs in one
// hop. Empty fields are silently dropped — no "Unknown" placeholders.
export function ClassificationPanel({
  cweId,
  owaspCategory,
  riskScore,
  confidence,
  ruleId,
}: ClassificationPanelProps) {
  const items: Array<{
    label: string;
    value: string;
    href?: string;
    accent?: string;
  }> = [];

  if (cweId !== undefined && cweId !== null && cweId > 0) {
    items.push({
      label: "CWE",
      value: `CWE-${cweId}`,
      href: `https://cwe.mitre.org/data/definitions/${cweId}.html`,
    });
  }
  if (owaspCategory) {
    items.push({
      label: "OWASP",
      value: owaspCategory,
      href: owaspHref(owaspCategory),
    });
  }
  if (riskScore !== undefined && riskScore !== null && riskScore > 0) {
    items.push({
      label: "Risk Score",
      value: riskScore.toFixed(1),
      accent: riskAccent(riskScore),
    });
  }
  if (confidence) {
    items.push({
      label: "Confidence",
      value: confidence.toUpperCase(),
      accent: confidenceAccent(confidence),
    });
  }
  if (ruleId) {
    items.push({ label: "Rule", value: ruleId });
  }

  if (items.length === 0) {
    return null;
  }

  return (
    <div className="rounded-lg border bg-surface-1 p-4">
      <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-3">
        Classification
      </h4>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2.5">
        {items.map((item) => (
          <div key={item.label} className="flex items-center justify-between gap-3">
            <dt className="text-xs text-muted-foreground">{item.label}</dt>
            <dd>
              {item.href ? (
                <a
                  href={item.href}
                  target="_blank"
                  rel="noreferrer noopener"
                  className={`inline-flex items-center gap-1 text-sm font-mono font-medium hover:underline ${item.accent ?? "text-foreground"}`}
                >
                  {item.value}
                  <ExternalLink className="h-3 w-3 opacity-60" />
                </a>
              ) : (
                <span className={`text-sm font-mono font-medium ${item.accent ?? "text-foreground"}`}>
                  {item.value}
                </span>
              )}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function owaspHref(cat: string): string | undefined {
  // OWASP categories look like "A03:2021". Map to the official page.
  const m = cat.match(/^A(\d+):(\d{4})$/);
  if (!m) return undefined;
  const num = m[1].padStart(2, "0");
  // OWASP Top 10 2021 URL pattern.
  // The slug after the number is fixed per category — too brittle to encode
  // here, so we link to the index page filtered to the year.
  return `https://owasp.org/Top10/A${num}_${m[2]}/`;
}

function riskAccent(score: number): string {
  if (score >= 9) return "text-severity-critical";
  if (score >= 7) return "text-severity-high";
  if (score >= 4) return "text-severity-medium";
  return "text-severity-low";
}

function confidenceAccent(c: string): string {
  switch (c.toLowerCase()) {
    case "high":
      return "text-severity-high";
    case "medium":
      return "text-severity-medium";
    case "low":
      return "text-muted-foreground";
    default:
      return "text-foreground";
  }
}

interface TagListProps {
  tags?: string[];
}

// TagList renders the searchable label chips. Special-cases the "owasp:Axx"
// tags so they get the accent treatment.
export function TagList({ tags }: TagListProps) {
  if (!tags || tags.length === 0) return null;
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {tags.map((tag) => (
        <span
          key={tag}
          className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium border ${tagAccent(tag)}`}
        >
          {tag}
        </span>
      ))}
    </div>
  );
}

function tagAccent(tag: string): string {
  if (tag.startsWith("owasp:")) {
    return "border-primary/40 bg-primary/10 text-primary";
  }
  if (tag === "passive") {
    return "border-muted-foreground/30 bg-muted text-muted-foreground";
  }
  return "border-border bg-muted/50 text-foreground";
}
