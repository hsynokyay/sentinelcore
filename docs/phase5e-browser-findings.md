# Phase 5e: Browser-Derived Findings and Correlation Enrichment

**Status:** Implemented
**Branch:** phase2/api-dast

## Overview

Phase 5e turns browser crawl observations into deterministic security findings and publishes them to the existing DAST findings pipeline for correlation with SAST and vulnerability intelligence.

## Architecture

```
PageResults (from crawler)
    ↓
AnalyzePages() — observation rules engine
    ↓
Observations (raw, preserved)  →  Findings (derived, with CWE/confidence)
                                      ↓
                                 BrowserScanResult.Findings
                                      ↓
                                 NATS scan.results.dast (HMAC signed)
                                      ↓
                                 Correlation Engine (existing)
```

## Observation → Finding Pipeline

Browser observations are raw signals. Findings are derived from observations only when:
1. The observation matches a defined rule with CWE mapping
2. The confidence level meets the minimum threshold
3. The evidence is concrete (not speculative)

### Finding Generation Rules

| Rule ID | Observation | CWE | Severity | Confidence | Category |
|---------|------------|-----|----------|-----------|----------|
| BROWSER-001 | POST/PUT/DELETE form missing CSRF token | 352 | medium | high | csrf |
| BROWSER-002 | Cookie missing Secure or HttpOnly flag | 614 | medium | high | cookie_security |
| BROWSER-003 | HTTPS page loads HTTP resources | 319 | medium | high | mixed_content |
| BROWSER-004 | Form submits to HTTP from HTTPS page | 319 | high | high | mixed_content |
| BROWSER-005 | Missing security response headers | 693 | low | high | headers |
| BROWSER-006 | Password field allows autocomplete | 525 | low | medium | information_exposure |
| BROWSER-007 | Excessive inline scripts (>= 10) | 79 | info | low | xss |

### Confidence Controls

- **High confidence**: Deterministic detection (missing CSRF field, HTTP resource on HTTPS page)
- **Medium confidence**: Heuristic detection (autocomplete on password fields)
- **Low confidence**: Informational only (inline script count)
- No finding is generated without a matching rule and CWE

## Observation Model

```go
type Observation struct {
    Type       ObservationType // e.g., "missing_csrf_token"
    URL        string          // page where observed
    Detail     string          // human-readable description
    Element    string          // CSS selector or element description
    Confidence string          // high, medium, low
    Severity   string          // critical, high, medium, low, info
    CWEID      int             // CWE identifier
    RuleID     string          // e.g., "BROWSER-001"
}
```

Observations are preserved separately in `AnalysisResult.Observations` — they are not lost when findings are generated.

## Fingerprinting and Dedup

Each finding gets a deterministic fingerprint:
```
SHA-256(scanJobID | ruleID | url | detail)
```

This ensures:
- Same observation on the same page produces the same fingerprint
- Re-scanning doesn't create duplicate findings
- The correlation engine can deduplicate via the existing `Fingerprint` field

## Correlation Integration

Browser findings are published as `finding_type: "dast"` on the existing `scan.results.dast` NATS subject. The correlation engine already handles DAST findings and will:
- Deduplicate via fingerprint
- Cross-correlate with SAST findings using 4-axis scoring (CWE 0.40, parameter 0.25, endpoint 0.20, temporal 0.15)
- Apply risk scoring with correlation boost

Browser findings that have CWE mappings will match SAST findings with the same or related CWE categories. For example:
- BROWSER-001 (CSRF, CWE-352) correlates with SAST findings for missing CSRF validation
- BROWSER-003 (mixed content, CWE-319) correlates with SAST findings for cleartext transmission

## Files

| File | Purpose |
|------|---------|
| `internal/browser/observations.go` | Observation types, rules, RuleByType lookup |
| `internal/browser/analyzer.go` | AnalyzePages: CSRF, mixed content, form-to-HTTP, inline scripts, autocomplete |
| `internal/browser/worker.go` | Updated: runs analyzer after crawl, appends findings to result |

## Test Coverage

| Test File | Tests | Coverage |
|-----------|-------|---------|
| `observations_test.go` | 7 tests | Rule completeness (CWE, category, severity, confidence, unique IDs) |
| `analyzer_test.go` | 14 tests | CSRF detection/skip, form-to-HTTP, mixed content, inline scripts, autocomplete, error page skip, deterministic fingerprints |
