# Phase 5d: Safe Browser Interaction

**Status:** Implemented
**Branch:** phase2/api-dast

## Overview

Phase 5d adds safe click discovery and interaction to the browser crawler, enabling SPA route discovery and richer DOM evidence capture without introducing destructive behavior.

## Safety Model

**Default behavior:** Non-destructive. Only elements classified as `ClickSafe` are interacted with. Form submission remains disabled. Unknown elements are treated as unsafe.

### Click Classification Rules

| Priority | Rule | Result |
|----------|------|--------|
| 1 | Destructive keyword in text (delete, remove, cancel, pay, ...) | Unsafe |
| 2 | Input type: submit, reset, file | Unsafe |
| 3 | button[type=submit] | Unsafe |
| 4 | Safe ARIA role (tab, menuitem, link, treeitem, switch) | Safe |
| 5 | Anchor with href | Safe |
| 6 | Safe CSS class pattern (nav, menu, tab, toggle, accordion, dropdown, pagination) | Safe |
| 7 | button[type=button] (explicit non-submitting) | Safe |
| 8 | Button without type (HTML default = submit in forms) | Unsafe |
| 9 | No matching rule | Unknown (treated as unsafe) |

**Key invariant:** Destructive keywords always override safe classification. A tab with text "Delete All" is still classified as unsafe.

### Budgets

| Limit | Value | Enforcement |
|-------|-------|-------------|
| Max safe clicks per page | 10 | Hard limit in interactor |
| Max crawl depth | 3 | CrawlState budget |
| Max URLs | 500 | CrawlState budget |
| Max duration | 30 min | CrawlState budget |

## Architecture

```
Crawler.visitPage(url)
  ├─ Navigate + WaitReady
  ├─ Extract links (a[href])
  ├─ Extract forms (action, method, fields, CSRF)
  ├─ Discover click targets (buttons, roles, data-toggle, etc.)
  ├─ Classify each target: Safe / Unsafe / Unknown
  ├─ Click safe targets (max 10 per page)
  │   ├─ Observe: did URL change? (SPA route discovery)
  │   └─ Observe: did DOM change? (content disclosure)
  └─ If click triggered navigation to in-scope URL → enqueue
```

## New Data Model

### ClickTarget
```go
type ClickTarget struct {
    Selector string      // CSS selector
    Tag      string      // element tag
    Text     string      // visible text (max 200 chars)
    Role     string      // ARIA role
    Href     string      // href if present
    Type     string      // button/input type
    Classes  string      // CSS classes
    Safety   ClickSafety // safe/unsafe/unknown
}
```

### InteractionResult
```go
type InteractionResult struct {
    Target       ClickTarget   // which element was clicked
    TriggeredNav bool          // did the click cause navigation?
    NewURL       string        // URL after click (if navigation occurred)
    DOMChanged   bool          // did visible DOM content change?
    Duration     time.Duration
    Error        string
}
```

### PageEvidence (new)
```go
type PageEvidence struct {
    PageURL       string         // page this evidence belongs to
    DOMSnapshot   *DOMSnapshot   // redacted DOM snapshot
    Screenshot    *dast.Evidence // screenshot with blur (existing model)
    NetworkLog    []NetworkEntry // network requests during page load
    CapturedAt    time.Time
}
```

### DOMSnapshot (new)
```go
type DOMSnapshot struct {
    URL        string // page URL
    Title      string // page title
    BodyText   string // visible text, redacted, max 64KB
    FormCount  int    // number of forms
    LinkCount  int    // number of links
    ScriptTags int    // number of inline scripts
    SHA256     string // integrity hash
}
```

## Evidence Flow

1. Crawler visits page → extracts links, forms, click targets
2. Safe interactor clicks safe elements → observes navigation/DOM changes
3. For pages with interesting content (forms or interactions):
   - Navigate back to page
   - Capture DOM snapshot (redacted via `SensitivePatterns`)
   - Capture screenshot (with CSS blur on inputs, password replacement)
   - Bundle into `PageEvidence`

## Files

| File | Purpose |
|------|---------|
| `internal/browser/clickable.go` | ClickTarget type, ClassifyClick rules, JS extraction |
| `internal/browser/interact.go` | SafeInteractor: discover targets, click safe ones, observe results |
| `internal/browser/dom_evidence.go` | DOMSnapshot, PageEvidence, NetworkEntry, evidence capture |
| `internal/browser/crawl_types.go` | Updated PageResult with ClickTargets, Interactions, Evidence |
| `internal/browser/crawler.go` | Updated to discover+click safe targets after each page visit |
| `internal/browser/worker.go` | Updated to capture evidence for interesting pages |

## Test Coverage

| Test File | Tests |
|-----------|-------|
| `clickable_test.go` | 24 subtests: safe/unsafe/unknown classification, keyword override, case sensitivity |
| `interact_test.go` | 4 tests: constructor, unsafe skipping, budget enforcement, result fields |
| `dom_evidence_test.go` | 4 tests: snapshot fields, evidence fields, network entry, max text size |
