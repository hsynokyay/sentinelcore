# Phase 5f: Browser Authentication and State Variance Analysis

**Status:** Implemented
**Branch:** phase2/api-dast

## Overview

Phase 5f compares browser-observed application behavior across anonymous and authenticated states to detect access control anomalies, exposure drift, and auth-dependent attack surface changes.

## Architecture

```
BrowserScanJob (with AuthConfig)
    ↓
ExecuteScan()
    ├─ Authenticated crawl (full budget)
    │   → pages, findings, evidence
    │   → SnapshotFromPages(authenticated, pages)
    │
    ├─ Anonymous crawl (reduced budget: 100 URLs, depth 2, 25% time)
    │   → separate Chrome context, no auth injection
    │   → SnapshotFromPages(anonymous, pages)
    │
    └─ ComputeVariance(anon, auth)
        → AnalyzeVariance(variance, scanJobID)
        → variance findings appended to result
```

## Auth State Comparison Model

### CrawlSnapshot

Reduced representation of crawl results for comparison:

```go
type CrawlSnapshot struct {
    State       AuthState              // anonymous or authenticated
    URLs        map[string]bool        // normalized visited URLs
    Forms       map[string]FormSummary // URL → form summary
    ClickCount  int
    PageCount   int
}
```

### AuthStateVariance

Diff between anonymous and authenticated snapshots:

```go
type AuthStateVariance struct {
    AuthOnlyURLs  []string                  // protected content (expected)
    AnonOnlyURLs  []string                  // suspicious: anon access to hidden routes
    AuthOnlyForms map[string]FormSummary    // admin/settings forms (expected)
    AnonOnlyForms map[string]FormSummary    // concerning: hidden anon-accessible forms
    SharedURLs    []string                  // common surface
}
```

## Finding Generation Rules

| Rule ID | Observation | CWE | Severity | Confidence | Generates Finding? |
|---------|------------|-----|----------|------------|-------------------|
| VARIANCE-001 | Auth-only route | — | info | high | No (expected behavior) |
| VARIANCE-002 | Anon-only route (hidden from auth) | 284 | medium | medium | **Yes** |
| VARIANCE-003 | Auth-only form | — | info | high | No (expected) |
| VARIANCE-004 | Anon-only form (hidden from auth) | 284 | high | medium | **Yes** |
| VARIANCE-005 | Surface expansion >= 2x with >= 5 auth-only routes | — | info | high | No (observation only) |

### Finding philosophy

- **Auth-only routes/forms** are expected (protected content). Logged as observations, not findings.
- **Anon-only routes** are suspicious — a route visible anonymously but hidden when authenticated may indicate access control drift or misconfiguration. Generates medium-severity finding.
- **Anon-only forms** are concerning — state-changing forms accessible anonymously but hidden after login may indicate hidden admin functionality or auth bypass. Generates high-severity finding.
- **Surface expansion** is informational — logged when auth more than doubles the visible surface.
- No finding is generated without directly observed evidence.

## Anonymous Crawl Budget

The anonymous crawl uses reduced limits to avoid doubling scan time:

| Parameter | Anonymous | Authenticated |
|-----------|-----------|---------------|
| MaxURLs | min(job.MaxURLs, 100) | job.MaxURLs (default 500) |
| MaxDepth | min(job.MaxDepth, 2) | job.MaxDepth (default 3) |
| MaxDuration | job.MaxDuration / 4 | job.MaxDuration (default 30m) |

The anonymous crawl uses a separate Chrome context (fresh profile, no cookies/headers) to ensure clean state isolation.

## Correlation Enrichment

Variance findings are published as `finding_type: "dast"` with `finding_source: "browser_variance"` metadata. This enables:

- SAST correlation: CWE-284 (access control) variance findings correlate with SAST findings for missing authorization checks
- API DAST correlation: anonymous-accessible routes found by browser can be cross-checked against API DAST endpoint coverage
- Deterministic fingerprints enable dedup across scan cycles

## Files

| File | Purpose |
|------|---------|
| `internal/browser/authstate.go` | CrawlSnapshot, AuthStateVariance, ComputeVariance |
| `internal/browser/variance_findings.go` | VarianceRules, AnalyzeVariance, finding generation |
| `internal/browser/variance_crawl.go` | RunAnonymousCrawl (separate Chrome, no auth) |
| `internal/browser/worker.go` | Updated: dual-crawl + variance analysis when authenticated |

## Test Coverage

| Test File | Tests | Coverage |
|-----------|-------|---------|
| `authstate_test.go` | 7 tests | Snapshot building, URL diff, form diff, empty snapshots |
| `variance_findings_test.go` | 10 tests | Rule validation, finding generation for anon-only routes/forms, auth-only routes (no findings), surface expansion, deterministic fingerprints |
