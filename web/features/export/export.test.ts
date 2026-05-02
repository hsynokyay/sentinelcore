/**
 * Type-level smoke test for export formatters. Validated by `tsc --noEmit`.
 */
import { exportFindingMarkdown } from "./finding-export";
import { exportScanReportMarkdown, type ScanReportData } from "./scan-report";
import { downloadAsFile, safeFilename } from "./download";
import type { Finding, Scan } from "@/lib/types";

const _finding: Finding = {
  id: "f-1",
  project_id: "p-1",
  scan_id: "s-1",
  finding_type: "sast",
  severity: "high",
  status: "new",
  title: "Test Finding",
  description: "Test",
  created_at: "2026-01-01T00:00:00Z",
  remediation: {
    title: "Fix",
    summary: "Summary",
    why_it_matters: "Matters",
    how_to_fix: "1. Do this\n2. Do that",
    unsafe_example: "bad",
    safe_example: "good",
    verification_checklist: ["Check 1"],
    references: [{ title: "CWE-1", url: "https://example.com" }],
  },
  taint_paths: [
    { step_index: 0, file_path: "Foo.java", line_start: 10, step_kind: "source", detail: "source" },
    { step_index: 1, file_path: "Foo.java", line_start: 15, step_kind: "sink", detail: "sink" },
  ],
};

// Finding export produces a string.
const _md: string = exportFindingMarkdown(_finding);

// Scan report export produces a string.
const _scan: Scan = {
  id: "s-1",
  project_id: "p-1",
  scan_type: "sast",
  status: "completed",
  progress: 100,
  created_at: "2026-01-01T00:00:00Z",
};
const _data: ScanReportData = { scan: _scan, findings: [_finding] };
const _report: string = exportScanReportMarkdown(_data);

// Download helper types.
const _fn: string = safeFilename("Test Title!", ".md");

export { _md, _report, _fn };
