/**
 * Type-level smoke test for the ticket formatter. This file is type-checked
 * by `tsc --noEmit` and validates that the formatter produces the expected
 * shape without a runtime test runner.
 *
 * For runtime validation, the formatter is exercised by the live E2E
 * verification: copy-for-ticket output is verified against the API response.
 */
import { formatTicketHandoff, formatChecklist, formatSafeExample } from "./ticket-formatter";
import type { Finding, RemediationBlock } from "@/lib/types";

// Type assertion: formatTicketHandoff accepts a Finding and returns string.
const _finding: Finding = {
  id: "f-1",
  project_id: "p-1",
  scan_id: "s-1",
  finding_type: "sast",
  severity: "high",
  status: "new",
  title: "Test",
  description: "Test",
  created_at: "2026-01-01T00:00:00Z",
};
const _output: string = formatTicketHandoff(_finding);
const _checklist: string = formatChecklist(["A", "B"]);
const _example: string = formatSafeExample("code");

// With remediation.
const _remediation: RemediationBlock = {
  title: "Test",
  summary: "Test",
  why_it_matters: "Test",
  how_to_fix: "1. Step 1\n2. Step 2",
  unsafe_example: "bad",
  safe_example: "good",
  verification_checklist: ["Check 1"],
  references: [{ title: "CWE-1", url: "https://example.com" }],
};
const _withRemediation: string = formatTicketHandoff({
  ..._finding,
  remediation: _remediation,
  rule_id: "SC-TEST-001",
});

// Unused exports to suppress "declared but never read" — the point
// is compile-time type validation, not runtime execution.
export { _output, _checklist, _example, _withRemediation };
