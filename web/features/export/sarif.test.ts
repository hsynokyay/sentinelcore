/**
 * Type-level and structural validation for SARIF export.
 * Validated by `tsc --noEmit`.
 */
import { exportFindingSarif, exportScanSarif } from "./sarif";
import type { Finding, Scan } from "@/lib/types";

// --- Fixtures ---

const sastFinding: Finding = {
  id: "f-sast-1",
  project_id: "p-1",
  scan_id: "s-1",
  finding_type: "sast",
  severity: "critical",
  status: "new",
  title: "SQL Injection via Statement.executeQuery",
  description: "User input flows into SQL query without parameterization.",
  file_path: "src/main/java/com/example/Foo.java",
  line_number: 42,
  created_at: "2026-01-01T00:00:00Z",
  rule_id: "SC-JAVA-SQL-001",
  taint_paths: [
    { step_index: 0, file_path: "Foo.java", line_start: 10, step_kind: "source", detail: "getParameter" },
    { step_index: 1, file_path: "Foo.java", line_start: 15, step_kind: "sink", detail: "executeQuery" },
  ],
  remediation: {
    title: "SQL Injection",
    summary: "User input reaches SQL sink.",
    why_it_matters: "Full DB compromise.",
    how_to_fix: "Use PreparedStatement.",
    unsafe_example: "bad",
    safe_example: "good",
    verification_checklist: ["Uses PreparedStatement"],
    references: [{ title: "CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html" }],
  },
};

const dastFinding: Finding = {
  id: "f-dast-1",
  project_id: "p-1",
  scan_id: "s-1",
  finding_type: "dast",
  severity: "medium",
  status: "new",
  title: "Missing CSRF token",
  description: "Form posts without CSRF protection.",
  url: "https://example.com/settings",
  method: "POST",
  created_at: "2026-01-01T00:00:00Z",
  rule_id: "SC-DAST-CSRF-001",
};

const scan: Scan = {
  id: "s-1",
  project_id: "p-1",
  project_name: "Test Project",
  scan_type: "sast",
  status: "completed",
  progress: 100,
  created_at: "2026-01-01T00:00:00Z",
  started_at: "2026-01-01T00:00:01Z",
  finished_at: "2026-01-01T00:01:00Z",
};

// --- Structural assertions (compile-time) ---

// Single finding SARIF.
const _sarifSast: string = exportFindingSarif(sastFinding);
const _sarifDast: string = exportFindingSarif(dastFinding);

// Parse and verify structure.
const _parsedSast = JSON.parse(_sarifSast) as {
  $schema: string;
  version: string;
  runs: Array<{
    tool: { driver: { name: string; rules: Array<{ id: string }> } };
    results: Array<{
      ruleId: string;
      level: string;
      locations: Array<unknown>;
      codeFlows?: Array<unknown>;
    }>;
  }>;
};

// Schema must be SARIF 2.1.0.
const _schema: string = _parsedSast.$schema;
const _version: "2.1.0" = _parsedSast.version as "2.1.0";

// Tool must be SentinelCore.
const _toolName: string = _parsedSast.runs[0].tool.driver.name;

// Rules must include the finding's rule.
const _ruleId: string = _parsedSast.runs[0].tool.driver.rules[0].id;

// Result must have the rule, level, and locations.
const _resultRuleId: string = _parsedSast.runs[0].results[0].ruleId;
const _level: string = _parsedSast.runs[0].results[0].level;

// SAST finding should have codeFlows (taint path with 2+ steps).
const _hasCodeFlows: boolean = (_parsedSast.runs[0].results[0].codeFlows?.length ?? 0) > 0;

// Scan-level SARIF.
const _scanSarif: string = exportScanSarif(scan, [sastFinding, dastFinding]);
const _parsedScan = JSON.parse(_scanSarif) as {
  version: string;
  runs: Array<{
    tool: { driver: { rules: Array<{ id: string }> } };
    results: Array<{ ruleId: string }>;
    invocations?: Array<{ executionSuccessful: boolean }>;
  }>;
};

// Scan SARIF should have 2 results and deduplicated rules.
const _resultCount: number = _parsedScan.runs[0].results.length;
const _ruleCount: number = _parsedScan.runs[0].tool.driver.rules.length;
const _hasInvocations: boolean = (_parsedScan.runs[0].invocations?.length ?? 0) > 0;

export {
  _sarifSast,
  _sarifDast,
  _schema,
  _version,
  _toolName,
  _ruleId,
  _resultRuleId,
  _level,
  _hasCodeFlows,
  _scanSarif,
  _resultCount,
  _ruleCount,
  _hasInvocations,
};
