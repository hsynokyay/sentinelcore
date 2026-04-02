# Phase 5c: Browser Crawl MVP

**Status:** Implemented
**Branch:** phase2/api-dast
**Prerequisite:** Phase 5b (Browser Worker Security Foundations)

## Overview

Phase 5c adds a safe, shallow browser crawler on top of the hardened browser worker runtime. The crawler discovers page structure (links, forms) within scope constraints but does NOT submit forms or perform destructive actions by default.

## Crawl Architecture

```
BrowserWorker.ExecuteScan()
    ↓
Crawler.Crawl(ctx, crawlState, chromeCtx)
    ↓
BFS loop: for crawlState.CanContinue()
    ↓
    Dequeue URL → Scope validate → Navigate → Extract links+forms → Enqueue
    ↓
    PageResult{URL, Title, Links, Forms, LoadTime}
```

## Crawl Budget Model

| Limit | Default | Enforcement |
|-------|---------|------------|
| MaxDepth | 3 | URLs at depth > MaxDepth are not enqueued |
| MaxURLs | 500 | Crawl stops when URLCount reaches limit |
| MaxDuration | 30 min | Crawl stops when wall-clock time exceeds limit |
| PageTimeout | 30 sec | Per-page navigation timeout |

## URL Normalization and Dedup

Every discovered URL passes through `NormalizeURL()` before enqueue:

1. Lowercase scheme and host
2. Strip fragments (`#section`)
3. Remove default ports (`:80` for HTTP, `:443` for HTTPS)
4. Remove trailing slashes (except root `/`)
5. Sort query parameters alphabetically
6. Reject non-HTTP schemes (`javascript:`, `data:`, `mailto:`, `ftp:`)

Normalized URLs are stored in a visited set. Duplicate URLs (including fragment variants) are never re-visited.

## Form Discovery

Forms are discovered but NOT submitted (default `SubmitForms=false`).

For each discovered form:
- **Action URL** extracted and resolved against page base
- **Method** (GET/POST)
- **Fields** with name and type
- **CSRF detection**: hidden field with name containing "csrf", "_token", "authenticity_token", or "xsrf"
- **Safety classification**: `IsDestructiveAction()` checks action URL and button text against 12 destructive keywords (delete, remove, cancel, unsubscribe, pay, purchase, transfer, send, destroy, drop, terminate, revoke)

## Scope Enforcement During Crawl

Every discovered URL is validated against the scope enforcer BEFORE navigation:

```go
if c.enforcer.CheckRequest(ctx, resolvedURL) != nil {
    // URL is out of scope — skip, do not enqueue
    continue
}
```

This works in conjunction with the three-layer enforcement from Phase 5b:
- **Layer 1 (CDP)**: Interceptor blocks any network request Chrome makes to out-of-scope URLs
- **Layer 2 (iptables)**: Kernel blocks connections to private/reserved IPs
- **Layer 3 (Monitor)**: IP validation on responses, WebSocket URL validation

## New Files

| File | Purpose |
|------|---------|
| `internal/browser/crawl_types.go` | CrawlState, CrawlEntry, PageResult, FormInfo, FormField |
| `internal/browser/normalize.go` | NormalizeURL, ResolveURL |
| `internal/browser/crawler.go` | Crawler with BFS traversal, form discovery, CSRF detection |

## Test Coverage

| Test File | Tests | Coverage |
|-----------|-------|---------|
| `crawl_types_test.go` | 8 tests | Budget enforcement, dedup, depth limits, invalid URLs |
| `normalize_test.go` | 24 subtests | URL normalization edge cases, relative URL resolution |
| `crawler_test.go` | 7 tests, 36+ subtests | Scope filtering, form safety, CSRF detection, depth tracking |
