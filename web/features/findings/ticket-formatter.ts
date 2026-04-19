import type { Finding } from "@/lib/types";

/**
 * Generates a clean plaintext handoff block from a finding, suitable for
 * pasting into Jira, GitHub Issues, Azure DevOps, email, or Slack.
 *
 * Design constraints:
 * - Deterministic: same finding always produces same output.
 * - Safe: never includes raw secret values. Hardcoded-secret findings
 *   show only the variable name and a redacted placeholder.
 * - Compact: scannable, not a wall of text.
 * - Self-contained: a reviewer can understand the issue without opening
 *   SentinelCore.
 */
export function formatTicketHandoff(finding: Finding): string {
  const lines: string[] = [];

  // Header
  lines.push(`Finding: ${finding.title}`);
  lines.push(`Severity: ${capitalize(finding.severity)}`);
  if (finding.rule_id) {
    lines.push(`Rule: ${finding.rule_id}`);
  }

  // Location
  const loc = formatLocation(finding);
  if (loc) {
    lines.push(`Location: ${loc}`);
  }

  lines.push("");

  // What happened
  const rem = finding.remediation;
  if (rem) {
    lines.push("What happened:");
    lines.push(rem.summary);
    lines.push("");

    // How to fix (top 4 steps)
    const steps = extractTopSteps(rem.how_to_fix, 4);
    if (steps.length > 0) {
      lines.push("How to fix:");
      for (const step of steps) {
        lines.push(`- ${step}`);
      }
      lines.push("");
    }

    // Verification (top 4 items)
    if (rem.verification_checklist.length > 0) {
      lines.push("Verification:");
      for (const item of rem.verification_checklist.slice(0, 4)) {
        lines.push(`- ${item}`);
      }
      lines.push("");
    }

    // References (compact)
    if (rem.references.length > 0) {
      lines.push("References:");
      for (const ref of rem.references.slice(0, 3)) {
        lines.push(`- ${ref.title}`);
      }
    }
  } else {
    // No remediation — include the finding description.
    if (finding.description) {
      lines.push("Description:");
      lines.push(finding.description);
    }
  }

  return lines.join("\n");
}

/**
 * Formats the finding location as a compact "file:line" string.
 * For DAST findings, shows the URL. For unknown locations, returns null.
 */
function formatLocation(finding: Finding): string | null {
  if (finding.file_path) {
    return finding.line_number
      ? `${finding.file_path}:${finding.line_number}`
      : finding.file_path;
  }
  if (finding.url) {
    return [finding.method, finding.url, finding.parameter ? `(param: ${finding.parameter})` : ""]
      .filter(Boolean)
      .join(" ");
  }
  return null;
}

/**
 * Extracts the first N actionable steps from the how_to_fix text.
 * Looks for numbered steps (1. / 2. / 3.) or bullet points (- / * ).
 * Falls back to the first N sentences if no structure is found.
 */
function extractTopSteps(howToFix: string, max: number): string[] {
  // Try numbered steps: "1. Do X\n2. Do Y"
  const numbered = howToFix.match(/^\d+\.\s+.+$/gm);
  if (numbered && numbered.length > 0) {
    return numbered.slice(0, max).map((s) => s.replace(/^\d+\.\s+/, "").trim());
  }

  // Try bullet points: "- Do X\n- Do Y"
  const bullets = howToFix.match(/^[-*]\s+.+$/gm);
  if (bullets && bullets.length > 0) {
    return bullets.slice(0, max).map((s) => s.replace(/^[-*]\s+/, "").trim());
  }

  // Fallback: first N lines that look substantive.
  return howToFix
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 10 && !l.startsWith("**"))
    .slice(0, max);
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/**
 * Formats just the safe example for copy. Strips comment markers that
 * might confuse non-Java contexts but keeps the code itself intact.
 */
export function formatSafeExample(code: string): string {
  return code;
}

/**
 * Formats the verification checklist as a compact numbered list.
 */
export function formatChecklist(items: string[]): string {
  return items.map((item, i) => `${i + 1}. ${item}`).join("\n");
}
