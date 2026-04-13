# CI/CD Integration Guide

SentinelCore exposes findings and scan reports via API endpoints that can be
consumed by CI/CD pipelines without the browser UI.

## API Endpoints

| Endpoint | Format | Description |
|---|---|---|
| `GET /api/v1/findings/{id}/export.md` | Markdown | Single finding report |
| `GET /api/v1/findings/{id}/export.sarif` | SARIF 2.1.0 | Single finding SARIF |
| `GET /api/v1/scans/{id}/report.md` | Markdown | Full scan report with executive summary |
| `GET /api/v1/scans/{id}/report.sarif` | SARIF 2.1.0 | Full scan SARIF with all findings |

All endpoints require Bearer token authentication.

## Authentication

```bash
# Get a token
TOKEN=$(curl -s -X POST https://sentinelcore.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ci@example.com","password":"..."}' \
  | jq -r '.access_token')
```

For CI automation, create a dedicated service account with `scans.read` and
`findings.read` permissions.

## curl Examples

```bash
# Fetch a scan report as Markdown
curl -H "Authorization: Bearer $TOKEN" \
  https://sentinelcore.example.com/api/v1/scans/$SCAN_ID/report.md \
  -o scan-report.md

# Fetch a scan report as SARIF
curl -H "Authorization: Bearer $TOKEN" \
  https://sentinelcore.example.com/api/v1/scans/$SCAN_ID/report.sarif \
  -o scan-results.sarif

# Fetch a single finding
curl -H "Authorization: Bearer $TOKEN" \
  https://sentinelcore.example.com/api/v1/findings/$FINDING_ID/export.sarif \
  -o finding.sarif
```

## GitHub Actions

```yaml
name: Security Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Fetch SentinelCore SARIF
        run: |
          TOKEN=$(curl -s -X POST $SENTINELCORE_URL/api/v1/auth/login \
            -H 'Content-Type: application/json' \
            -d '{"email":"${{ secrets.SC_USER }}","password":"${{ secrets.SC_PASS }}"}' \
            | jq -r '.access_token')

          curl -H "Authorization: Bearer $TOKEN" \
            $SENTINELCORE_URL/api/v1/scans/${{ env.SCAN_ID }}/report.sarif \
            -o sentinelcore.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sentinelcore.sarif
```

## GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - |
      TOKEN=$(curl -s -X POST $SENTINELCORE_URL/api/v1/auth/login \
        -H 'Content-Type: application/json' \
        -d "{\"email\":\"$SC_USER\",\"password\":\"$SC_PASS\"}" \
        | jq -r '.access_token')

      curl -H "Authorization: Bearer $TOKEN" \
        $SENTINELCORE_URL/api/v1/scans/$SCAN_ID/report.sarif \
        -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Azure DevOps

```yaml
- task: Bash@3
  displayName: 'Fetch SentinelCore SARIF'
  inputs:
    targetType: 'inline'
    script: |
      TOKEN=$(curl -s -X POST $(SENTINELCORE_URL)/api/v1/auth/login \
        -H 'Content-Type: application/json' \
        -d '{"email":"$(SC_USER)","password":"$(SC_PASS)"}' \
        | jq -r '.access_token')

      curl -H "Authorization: Bearer $TOKEN" \
        $(SENTINELCORE_URL)/api/v1/scans/$(SCAN_ID)/report.sarif \
        -o $(Build.ArtifactStagingDirectory)/sentinelcore.sarif

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)/sentinelcore.sarif'
    ArtifactName: 'security-reports'
```

## Content Types

| Format | Content-Type | Extension |
|---|---|---|
| Markdown | `text/markdown; charset=utf-8` | `.md` |
| SARIF | `application/json; charset=utf-8` | `.sarif` |

## SARIF Contents

The SARIF export includes:
- **Tool metadata**: SentinelCore name, version, information URI
- **Rules**: deduplicated rule definitions with CWE properties and remediation help
- **Results**: severity-mapped levels, locations, fingerprints, code flows
- **Invocations** (scan-level): timing and success status

See [SARIF Export documentation](sarif-export.md) for full field mapping.

## Safety

- No raw secrets are included in any export format
- Evidence descriptions use the same redacted form as the UI
- SARIF fingerprints use finding IDs, not sensitive data
- All exports respect RLS — users can only export findings they have access to

## Limitations

- Token-based auth only (no API keys yet)
- No webhook/callback on scan completion yet
- Scan SARIF fetches all findings synchronously (may be slow for large scans)
