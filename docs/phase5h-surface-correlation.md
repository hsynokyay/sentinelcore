# Phase 5h: Surface Correlation Enrichment

**Status:** Implemented
**Branch:** phase2/api-dast

## Overview

Phase 5h links the attack surface inventory to findings using deterministic matching heuristics, enabling downstream reporting that answers "which surface entries have security findings, and why?"

## Matching Heuristics

| Match Type | Score | Confidence | Description |
|-----------|-------|------------|-------------|
| `exact_url` | 1.0 | high | Surface URL exactly matches finding URL |
| `path_prefix` | 0.5–1.0 | medium–high | Surface URL path is a prefix of finding URL path (or vice versa), with ≥ 50% segment overlap |
| `form_action` | 0.9 | high | Form action URL matches finding URL |
| `parameter_name` | 0.8 | medium | Form field name matches finding parameter (case-insensitive) |

### Confidence mapping

| Score | Confidence |
|-------|-----------|
| ≥ 0.80 | high |
| ≥ 0.50 | medium |
| ≥ 0.30 | low |
| < 0.30 | none (not created) |

No speculative mappings — every correlation has an explicit match type, score, and explanation.

## Data Model

### SurfaceCorrelation

```go
type SurfaceCorrelation struct {
    SurfaceID    string           // inventory entry fingerprint
    FindingID    string           // finding ID
    MatchType    SurfaceMatchType // exact_url, path_prefix, form_action, parameter_name
    Score        float64          // 0.0–1.0
    Confidence   string           // high, medium, low
    Detail       string           // human-readable explanation
}
```

### EnrichmentResult

```go
type EnrichmentResult struct {
    Correlations []SurfaceCorrelation
    Stats        EnrichmentStats
}

type EnrichmentStats struct {
    TotalCorrelations int
    ByMatchType       map[string]int
    ByConfidence      map[string]int
    EnrichedEntries   int
}
```

## Integration

Enrichment runs after inventory building in `ExecuteScan`:

```
BuildInventory(pages, variance, findings)
    ↓
EnrichInventory(inventory, rawFindings)
    ↓
inventory.Entries[].FindingIDs updated
inventory.Stats recomputed
enrichment stats logged
```

Finding conversion: `dast.Finding` → `corr.RawFinding` with URL, Method, Parameter, Category, Fingerprint.

## Reporting Use Cases

| Query | Method | Answers |
|-------|--------|---------|
| "What's our public attack surface?" | `QueryByExposure(ExposurePublic)` | All publicly accessible routes, forms, endpoints |
| "Which surface entries have findings?" | `QueryWithFindings()` | Entries with security issues |
| "What forms are vulnerable?" | `QueryByType(SurfaceForm)` + check FindingIDs | Forms with CSRF/mixed content/other findings |
| "What's the auth-only surface?" | `QueryByExposure(ExposureAuthenticated)` | Protected content inventory |
| "How large is our attack surface?" | `inventory.Stats` | Totals by type, exposure, finding count |

## Files

| File | Purpose |
|------|---------|
| `internal/browser/surface_correlator.go` | EnrichInventory, matching heuristics, path overlap, fingerprinting |
| `internal/browser/surface_correlator_test.go` | 13 tests covering all match types, scoring, edge cases |
| `internal/browser/worker.go` | Enrichment wired after inventory building |

## Test Coverage

| Test | Coverage |
|------|---------|
| Exact URL match | Score 1.0, high confidence, finding ID association |
| Path prefix match | Score ≥ 0.5, overlap calculation |
| Form action match | Score 0.9, high confidence |
| Parameter name match | Score 0.8, medium confidence |
| No matches | 0 correlations, 0 enriched entries |
| Empty inputs | Graceful handling |
| Stats computation | Match type and confidence breakdown |
| Path overlap | 6 cases: identical, prefix, partial, no overlap, empty, root |
| Score to confidence | 8 threshold boundary tests |
| Correlation fingerprint | Deterministic, different inputs → different IDs |
