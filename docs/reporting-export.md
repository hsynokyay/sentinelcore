# Reporting & Export

## Supported Formats

SentinelCore supports Markdown export for:
- **Single finding** — full detail with remediation, trace, and references
- **Scan report** — executive summary + technical appendix

Markdown was chosen because it renders natively in:
- GitHub / GitLab (README, issues, wikis)
- Confluence / Notion
- Jira (with markdown support enabled)
- Any PDF converter (pandoc, etc.)

## Finding Export

Available from the finding detail page via the **Export** button.

Includes:
- Title, severity, status, rule ID
- Location (file:line for SAST, URL for DAST)
- Description
- Analysis trace (if present)
- Full remediation: why it matters, how to fix, safe example
- Verification checklist (as GitHub-style `- [ ]` checkboxes)
- References with clickable links

## Scan Report Export

Available from the scan detail page via the **Export Report** button.

Includes:

### Executive Summary
- Scan metadata (type, profile, target, timing)
- Total findings count
- Severity breakdown table with emoji indicators
- Top 5 remediation priorities
- Major exposure themes (auto-detected)

### Technical Appendix
- Every finding with severity, type, rule, location
- Description
- Analysis trace (if present)
- Remediation summary (first 2 sentences)
- Top 3 references

## Safety / Redaction

- **Secrets are never included** in any export. Hardcoded-secret findings
  show only the variable name and fix guidance.
- **Evidence descriptions** use the same redacted form as the UI.
- **Internal implementation details** are not exposed.
- All exports are safe for screenshots, demos, audits, and external sharing.

## How Exports Are Generated

Exports are generated entirely client-side from the API response data:
1. The frontend fetches the finding detail (or scan + findings for reports)
2. A pure TypeScript formatter produces Markdown
3. The browser downloads the result as a `.md` file

No server-side rendering or additional backend endpoints are required.

## Extending

The formatter architecture supports future additions:
- **HTML export**: render the Markdown to styled HTML
- **PDF export**: pipe Markdown through a headless renderer
- **SARIF export**: standard security results format for CI integration
- **CSV export**: tabular findings list for spreadsheet analysis

None of these are implemented yet.

## Files

```
web/features/export/finding-export.ts        — single-finding Markdown formatter
web/features/export/scan-report.ts           — scan report Markdown formatter
web/features/export/download.ts              — browser download utility
web/features/export/export-finding-button.tsx — finding detail export button
web/features/export/export-scan-report-button.tsx — scan detail export button
```
