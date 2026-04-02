# Phase 5g: Attack Surface Inventory and Exposure Mapping

**Status:** Implemented
**Branch:** phase2/api-dast

## Overview

Phase 5g builds a unified, queryable inventory of the application attack surface from browser crawl observations, API DAST data, and auth-state variance analysis.

## Inventory Model

### SurfaceEntry

Each discovered surface element becomes a `SurfaceEntry`:

```go
type SurfaceEntry struct {
    ID               string        // deterministic fingerprint
    ProjectID        string
    ScanJobID        string
    Type             SurfaceType   // route, form, api_endpoint, clickable
    URL              string        // normalized URL
    Method           string        // HTTP method or "CLICK"
    Exposure         ExposureLevel // public, authenticated, both, unknown
    Title            string
    Metadata         EntryMetadata // type-specific details
    FirstSeenAt      time.Time
    LastSeenAt       time.Time
    ScanCount        int           // how many scans have seen this entry
    FindingIDs       []string      // associated finding fingerprints
    ObservationCount int
}
```

### Surface Types

| Type | Source | Description |
|------|--------|-------------|
| `route` | Browser crawl | Navigable URL with title, depth |
| `form` | Browser crawl | HTML form with action, method, fields, CSRF status |
| `api_endpoint` | API DAST | REST/JSON endpoint (future integration) |
| `clickable` | Browser interaction | Unsafe/unknown interactive elements only (safe elements are expected navigation, excluded) |

### Exposure Levels

| Level | Meaning | Source |
|-------|---------|--------|
| `public` | Accessible anonymously | Variance: anon-only URLs |
| `authenticated` | Requires authentication | Variance: auth-only URLs |
| `both` | Accessible in both states | Variance: shared URLs |
| `unknown` | No auth comparison done | No variance data available |

## Inventory Builder

`BuildInventory()` constructs the inventory from:

1. **PageResults** from browser crawl → route entries, form entries, clickable entries
2. **AuthStateVariance** → exposure classification per URL
3. **Findings** → finding association per URL (indexed by normalized URL)

### Deduplication

Entries are fingerprinted by `SHA-256(surfaceType | normalizedURL | method)`, truncated to 16 hex chars. Duplicate entries update `LastSeenAt` and `ScanCount`.

### Filtering

- Error pages are excluded
- Safe clickables (navigation elements) are excluded — only unsafe/unknown clickables are attack surface
- Finding association uses normalized URL matching

## Query Support

The inventory supports three query patterns:

| Query | Method | Use Case |
|-------|--------|----------|
| By type | `QueryByType(SurfaceRoute)` | "Show all discovered routes" |
| By exposure | `QueryByExposure(ExposurePublic)` | "Show all publicly accessible surface" |
| With findings | `QueryWithFindings()` | "Show surface entries that have security findings" |

All queries return sorted results for deterministic output.

## Statistics

`ComputeStats()` calculates:

| Stat | Description |
|------|-------------|
| TotalEntries | Total inventory size |
| ByType | Count per surface type |
| ByExposure | Count per exposure level |
| RoutesWithForms | Routes that have form fields |
| UnsafeClickables | Elements classified as unsafe |
| EntriesWithFindings | Entries with associated security findings |

## Integration with Worker

The inventory is built at the end of `ExecuteScan`, after all crawling, analysis, and variance analysis is complete. It's attached to `BrowserScanResult.Inventory` and available for downstream reporting and correlation.

## Files

| File | Purpose |
|------|---------|
| `internal/browser/inventory.go` | SurfaceEntry, SurfaceInventory, query methods, fingerprinting |
| `internal/browser/inventory_builder.go` | BuildInventory from pages + variance + findings |
| `internal/browser/types.go` | Updated BrowserScanResult with Inventory field |
| `internal/browser/worker.go` | Inventory building wired after variance analysis |

## Test Coverage

| Test | Coverage |
|------|---------|
| Fingerprint determinism | Same inputs → same ID, different inputs → different ID |
| Inventory dedup | Duplicate entries update count, not create duplicates |
| Query by type | Routes, forms, clickables filtered correctly |
| Query by exposure | Public, authenticated, both filtered correctly |
| Query with findings | Only entries with finding associations returned |
| Stats computation | All stat fields computed correctly |
| Build from pages | Routes, forms, unsafe clickables extracted; errors excluded |
| Build with variance | Exposure levels assigned from variance data |
| Build empty | Empty input → empty inventory |
