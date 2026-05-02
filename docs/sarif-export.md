# SARIF Export

SentinelCore exports findings in [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) format, the industry standard for static and dynamic analysis results.

## Supported exports

| Export | Source | Button |
|---|---|---|
| **Single finding** | Finding detail page | "SARIF" button |
| **Full scan** | Scan detail page | "SARIF" button |

## What's included

### Tool metadata
- `name`: SentinelCore
- `version`: 1.0.0
- `informationUri`: deployment URL
- `rules`: deduplicated array of all rule definitions in the run

### Per-rule
- `id`: SentinelCore rule ID (e.g., `SC-JAVA-SQL-001`)
- `shortDescription`: finding title
- `fullDescription`: finding description
- `help.text`: remediation how-to-fix text
- `help.markdown`: full remediation with safe example
- `defaultConfiguration.level`: mapped from severity
- `properties.cwe`: CWE identifiers
- `properties.tags`: finding type + severity

### Per-result
- `ruleId` + `ruleIndex`
- `level`: `error` (critical/high), `warning` (medium), `note` (low/info)
- `message`: finding title + first sentence of description
- `locations`: file path + line for SAST, URL for DAST
- `fingerprints.sentinelcore/v1`: finding ID for cross-run dedup
- `codeFlows` (SAST only): taint path as threadFlow locations

### Invocations (scan-level only)
- `executionSuccessful`: based on scan status
- `startTimeUtc` / `endTimeUtc`: scan timing

## Usage with CI/CD platforms

### GitHub Code Scanning

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinelcore-scan.sarif
```

### Azure DevOps

Upload the `.sarif` file as a build artifact, then configure Advanced Security to ingest it.

### GitLab

Add to `.gitlab-ci.yml`:
```yaml
artifacts:
  reports:
    sast: sentinelcore-scan.sarif
```

### VS Code

Install the [SARIF Viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) and open the `.sarif` file.

## Severity mapping

| SentinelCore | SARIF level |
|---|---|
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | note |

## Limitations

- DAST findings use the URL as the artifact URI since SARIF's location model is file-oriented. Some viewers may not render these as clickable links.
- `codeFlows` are only populated for SAST findings with taint paths (2+ steps). Single-step findings (like weak crypto) don't generate a code flow.
- The remediation `help.markdown` field is populated when the finding has a remediation pack; otherwise it's omitted.
