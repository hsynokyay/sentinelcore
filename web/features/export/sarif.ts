/**
 * SARIF 2.1.0 export for SentinelCore findings.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 *
 * Produces JSON that is directly ingestible by:
 * - GitHub Code Scanning (via upload-sarif action)
 * - Azure DevOps Advanced Security
 * - GitLab SAST report ingestion
 * - any SARIF-compatible viewer (VS Code SARIF Viewer, etc.)
 *
 * Design:
 * - Deterministic: same findings always produce the same SARIF.
 * - Safe: no raw secret values in the output.
 * - Standards-aligned: only populates fields the spec defines. Does not
 *   fake unsupported fields.
 */
import type { Finding, Scan } from "@/lib/types";

// --- SARIF type definitions (subset of 2.1.0 spec) ---

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifToolDriver };
  results: SarifResult[];
  invocations?: SarifInvocation[];
}

interface SarifToolDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  help?: { text: string; markdown?: string };
  helpUri?: string;
  defaultConfiguration: { level: SarifLevel };
  properties?: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: SarifLocation[];
  fingerprints?: Record<string, string>;
  codeFlows?: SarifCodeFlow[];
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation?: {
    artifactLocation: { uri: string };
    region?: { startLine: number; startColumn?: number; endLine?: number };
  };
}

interface SarifCodeFlow {
  threadFlows: SarifThreadFlow[];
}

interface SarifThreadFlow {
  locations: SarifThreadFlowLocation[];
}

interface SarifThreadFlowLocation {
  location: SarifLocation;
  nestingLevel?: number;
  kinds?: string[];
  message?: { text: string };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  endTimeUtc?: string;
}

type SarifLevel = "error" | "warning" | "note" | "none";

// --- Public API ---

/**
 * Export a single finding as a complete SARIF log.
 */
export function exportFindingSarif(finding: Finding): string {
  const rule = findingToRule(finding);
  const result = findingToResult(finding, 0);
  const log = buildLog([rule], [result]);
  return JSON.stringify(log, null, 2);
}

/**
 * Export an entire scan as a SARIF log with all findings.
 */
export function exportScanSarif(scan: Scan, findings: Finding[]): string {
  // Deduplicate rules by ruleId.
  const ruleMap = new Map<string, SarifRule>();
  const ruleIndex = new Map<string, number>();
  const results: SarifResult[] = [];

  for (const f of findings) {
    const ruleId = effectiveRuleId(f);
    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, findingToRule(f));
      ruleIndex.set(ruleId, ruleMap.size - 1);
    }
    results.push(findingToResult(f, ruleIndex.get(ruleId)!));
  }

  const log = buildLog(
    Array.from(ruleMap.values()),
    results,
    scan.started_at
      ? [
          {
            executionSuccessful: scan.status === "completed",
            startTimeUtc: scan.started_at,
            endTimeUtc: scan.finished_at,
          },
        ]
      : undefined,
  );
  return JSON.stringify(log, null, 2);
}

// --- Internal helpers ---

function buildLog(
  rules: SarifRule[],
  results: SarifResult[],
  invocations?: SarifInvocation[],
): SarifLog {
  const run: SarifRun = {
    tool: {
      driver: {
        name: "SentinelCore",
        version: "1.0.0",
        informationUri: "https://sentinelcore.resiliencetech.com.tr",
        rules,
      },
    },
    results,
  };
  if (invocations) {
    run.invocations = invocations;
  }
  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [run],
  };
}

function findingToRule(f: Finding): SarifRule {
  const ruleId = effectiveRuleId(f);
  const rule: SarifRule = {
    id: ruleId,
    name: ruleId,
    shortDescription: { text: f.title },
    defaultConfiguration: { level: severityToLevel(f.severity) },
  };

  if (f.description) {
    rule.fullDescription = { text: f.description };
  }

  // Remediation as help text.
  if (f.remediation) {
    rule.help = {
      text: f.remediation.how_to_fix,
      markdown: buildHelpMarkdown(f),
    };
  }

  // CWE + OWASP as properties (GitHub Code Scanning reads these).
  const props: Record<string, unknown> = {};
  if (f.remediation?.references) {
    const cwe = f.remediation.references
      .filter((r) => r.title.startsWith("CWE-"))
      .map((r) => r.title);
    if (cwe.length > 0) {
      props["cwe"] = cwe;
    }
    const tags = [f.finding_type];
    if (f.severity) tags.push(f.severity);
    props["tags"] = tags;
  }
  if (Object.keys(props).length > 0) {
    rule.properties = props;
  }

  return rule;
}

function findingToResult(f: Finding, ruleIdx: number): SarifResult {
  const result: SarifResult = {
    ruleId: effectiveRuleId(f),
    ruleIndex: ruleIdx,
    level: severityToLevel(f.severity),
    message: { text: f.title + (f.description ? ". " + firstSentence(f.description) : "") },
    locations: [buildLocation(f)],
  };

  // Stable fingerprint for deduplication across runs.
  if (f.id) {
    result.fingerprints = {
      "sentinelcore/v1": f.id,
    };
  }

  // Taint path as codeFlow.
  if (f.taint_paths && f.taint_paths.length > 1) {
    result.codeFlows = [
      {
        threadFlows: [
          {
            locations: f.taint_paths.map((step) => ({
              location: {
                physicalLocation: {
                  artifactLocation: { uri: step.file_path },
                  region: { startLine: step.line_start },
                },
              },
              kinds: [step.step_kind],
              message: { text: step.detail },
            })),
          },
        ],
      },
    ];
  }

  return result;
}

function buildLocation(f: Finding): SarifLocation {
  if (f.file_path) {
    const loc: SarifLocation = {
      physicalLocation: {
        artifactLocation: { uri: f.file_path },
        region: { startLine: f.line_number || 1 },
      },
    };
    return loc;
  }
  // DAST findings use URL — SARIF doesn't have a great URL location model,
  // but we can use the URI field with the full URL.
  if (f.url) {
    return {
      physicalLocation: {
        artifactLocation: { uri: f.url },
        region: { startLine: 1 },
      },
    };
  }
  return {
    physicalLocation: {
      artifactLocation: { uri: "unknown" },
      region: { startLine: 1 },
    },
  };
}

function buildHelpMarkdown(f: Finding): string {
  const rem = f.remediation;
  if (!rem) return "";
  const parts: string[] = [];
  parts.push(`## ${rem.title}`);
  parts.push("");
  parts.push(rem.summary);
  parts.push("");
  parts.push("### How to Fix");
  parts.push("");
  parts.push(rem.how_to_fix);
  if (rem.safe_example) {
    parts.push("");
    parts.push("### Safe Example");
    parts.push("```");
    parts.push(rem.safe_example);
    parts.push("```");
  }
  return parts.join("\n");
}

function effectiveRuleId(f: Finding): string {
  if (f.rule_id) return f.rule_id;
  // Fallback for findings without a rule_id.
  return `sentinelcore/${f.finding_type}/${f.severity}`;
}

function severityToLevel(severity: string): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "warning";
  }
}

function firstSentence(text: string): string {
  const match = text.match(/^[^.!?]+[.!?]/);
  return match ? match[0].trim() : text.slice(0, 120);
}
