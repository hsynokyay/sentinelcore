# DAST Active Probe Expansion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 9 new active DAST probes (XXE, NoSQL injection, GraphQL introspection, JWT alg=none, JWT weak secret, CRLF injection, open redirect, mass assignment, prototype pollution) and 4 new response matchers, lifting active DAST coverage from 6 probes to 15.

**Architecture:** Two PRs. PR D1 adds new matchers (`BodyRegexMatcher`, `HeaderContainsMatcher`, `HeaderRegexMatcher`, `StatusDiffMatcher`) and extends `Endpoint` with `CapturedJWT` plus `TestCase` with `MinProfile`. PR D2 implements 9 probe generators, plumbs `scan_profile` through `GenerateTestCases`, adds unit + integration tests. No engine architecture changes — `TestCase` shape unchanged structurally; matchers slot into the existing `ResponseMatcher` interface.

**Tech Stack:** Go 1.23, `internal/dast/` package, `httptest.NewServer` for integration tests, `crypto/hmac`/`encoding/base64` for JWT probes (no external JWT library), standard `regexp` for body/header pattern matching.

**Spec reference:** `docs/superpowers/specs/2026-05-01-dast-probe-expansion-design.md`

---

## Working environment

- **Branch:** `feat/dast-probes-2026-05` cut from `phase2/api-dast` HEAD (`3708db5e` after spec commit).
- **Worktree:** `/Users/okyay/Documents/SentinelCore/.worktrees/dast-probes` (created in PR 0).
- **Build target:** `sentinelcore/dast-worker:pilot` is the deployed image; `cmd/dast-worker` is the entrypoint.
- **Server build:**
  ```
  rsync -az --delete --exclude .git --exclude .next --exclude node_modules \
    --exclude .worktrees --exclude '*.test' \
    ./ okyay@77.42.34.174:/tmp/sentinelcore-src/
  ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
    docker build --build-arg SERVICE=dast-worker -t sentinelcore/dast-worker:dast-prN ."
  ```
- **Deploy:**
  ```
  ssh okyay@77.42.34.174 "docker tag sentinelcore/dast-worker:dast-prN sentinelcore/dast-worker:pilot && \
    cd /opt/sentinelcore/compose && docker compose up -d dast-worker"
  ```
- **Rollback tag** taken once before PR D1:
  ```
  ssh okyay@77.42.34.174 "docker tag sentinelcore/dast-worker:pilot sentinelcore/dast-worker:pilot-pre-dast-expansion"
  ```
- **GitHub:** push after every commit (`git push -u origin feat/dast-probes-2026-05` first time, `git push` after).

---

## File structure

### New files

| Path | Responsibility |
|------|----------------|
| `internal/dast/matchers.go` | The four new response matchers and helpers |
| `internal/dast/matchers_test.go` | Hit/miss table tests for each matcher |

### Modified files

| Path | Reason |
|------|--------|
| `internal/dast/testcase.go` | Add `MinProfile string` field to `TestCase` |
| `internal/dast/generator.go` | Add `CapturedJWT string` to `Endpoint`; extend `GenerateTestCases` signature; add 9 probe generators with profile gating |
| `internal/dast/generator_test.go` | 9 new unit tests + 1 profile-gating test |
| `internal/dast/integration_test.go` | 3 end-to-end probe tests (XXE, JWT alg=none, prototype pollution) |
| `internal/dast/worker.go` | Pass `job.Profile` to `GenerateTestCases` |

---

## PR 0 — Pre-flight

- [ ] **Step 1: Verify clean state on phase2/api-dast**

```
cd /Users/okyay/Documents/SentinelCore
git status --short
git log --oneline -3
```

Expected: top commit is `3708db5e docs(spec): DAST active probe expansion ...`. STOP if not.

- [ ] **Step 2: Create branch + worktree**

```
git worktree add /Users/okyay/Documents/SentinelCore/.worktrees/dast-probes \
  -b feat/dast-probes-2026-05 phase2/api-dast
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-probes
git branch --show-current
```

Expected: `feat/dast-probes-2026-05`.

- [ ] **Step 3: Tag rollback image**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/dast-worker:pilot sentinelcore/dast-worker:pilot-pre-dast-expansion && \
  docker images | grep dast-worker | head -5"
```

Expected: `pilot-pre-dast-expansion` listed.

- [ ] **Step 4: Baseline tests**

```
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-probes
go test ./internal/dast/...
```

Expected: PASS for every package. STOP if anything fails.

---

## PR D1 — Matchers + Endpoint/TestCase extensions

### Task D1.1: BodyRegexMatcher

**Files:**
- Create: `internal/dast/matchers.go`
- Create: `internal/dast/matchers_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/dast/matchers_test.go`:
```go
package dast

import (
	"net/http"
	"regexp"
	"testing"
)

func TestBodyRegexMatcher_Hit(t *testing.T) {
	m := &BodyRegexMatcher{
		Pattern: regexp.MustCompile(`root:[^:]*:0:0:`),
		Reason:  "etc/passwd contents detected",
	}
	hit, reason := m.Match(&http.Response{}, []byte("root:x:0:0:root:/root:/bin/bash"))
	if !hit {
		t.Fatalf("expected hit, got miss")
	}
	if reason != "etc/passwd contents detected" {
		t.Errorf("reason = %q", reason)
	}
}

func TestBodyRegexMatcher_Miss(t *testing.T) {
	m := &BodyRegexMatcher{Pattern: regexp.MustCompile(`evil`), Reason: "x"}
	hit, _ := m.Match(&http.Response{}, []byte("nothing here"))
	if hit {
		t.Fatalf("expected miss")
	}
}
```

- [ ] **Step 2: Run test (expected: FAIL — type undefined)**

```
go test ./internal/dast/... -run TestBodyRegexMatcher 2>&1 | tail -5
```

Expected: build error mentioning `undefined: BodyRegexMatcher`.

- [ ] **Step 3: Create `internal/dast/matchers.go` with the matcher**

```go
package dast

import (
	"net/http"
	"regexp"
	"strings"
)

// BodyRegexMatcher fires when the regex matches the response body.
type BodyRegexMatcher struct {
	Pattern *regexp.Regexp
	Reason  string
}

func (m *BodyRegexMatcher) Match(_ *http.Response, body []byte) (bool, string) {
	if m.Pattern != nil && m.Pattern.Match(body) {
		return true, m.Reason
	}
	return false, ""
}

// HeaderContainsMatcher fires when a named header value contains the substring.
type HeaderContainsMatcher struct {
	Name      string
	Substring string
	Reason    string
}

func (m *HeaderContainsMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil {
		return false, ""
	}
	for _, v := range resp.Header.Values(m.Name) {
		if strings.Contains(v, m.Substring) {
			return true, m.Reason
		}
	}
	return false, ""
}

// HeaderRegexMatcher fires when a named header value matches the regex.
type HeaderRegexMatcher struct {
	Name    string
	Pattern *regexp.Regexp
	Reason  string
}

func (m *HeaderRegexMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil || m.Pattern == nil {
		return false, ""
	}
	for _, v := range resp.Header.Values(m.Name) {
		if m.Pattern.MatchString(v) {
			return true, m.Reason
		}
	}
	return false, ""
}

// StatusDiffMatcher fires when the probe response status differs from a
// recorded baseline status. The matcher is configured with the expected
// success-of-attack status; the worker is responsible for setting
// BaselineCode before invoking the matcher (left zero if no baseline was
// captured, in which case the matcher fires on ProbeCode alone — useful
// for static thresholds).
type StatusDiffMatcher struct {
	BaselineCode int
	ProbeCode    int
	Reason       string
}

func (m *StatusDiffMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil {
		return false, ""
	}
	if resp.StatusCode != m.ProbeCode {
		return false, ""
	}
	if m.BaselineCode == 0 || m.BaselineCode != m.ProbeCode {
		return true, m.Reason
	}
	return false, ""
}
```

- [ ] **Step 4: Verify the BodyRegex tests pass**

```
go test ./internal/dast/... -run TestBodyRegexMatcher -v 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 5: Commit + push**

```
git add internal/dast/matchers.go internal/dast/matchers_test.go
git commit -m "feat(dast): add BodyRegexMatcher + 3 sibling matchers (header/status-diff)"
git push -u origin feat/dast-probes-2026-05
```

### Task D1.2: HeaderContainsMatcher tests

**Files:**
- Modify: `internal/dast/matchers_test.go`

- [ ] **Step 1: Append tests**

Add to `internal/dast/matchers_test.go`:
```go
func TestHeaderContainsMatcher_Hit(t *testing.T) {
	m := &HeaderContainsMatcher{Name: "Set-Cookie", Substring: "pwn=1", Reason: "CRLF echo"}
	resp := &http.Response{Header: http.Header{"Set-Cookie": []string{"session=abc; pwn=1; path=/"}}}
	hit, reason := m.Match(resp, nil)
	if !hit || reason != "CRLF echo" {
		t.Fatalf("expected hit with reason 'CRLF echo', got hit=%v reason=%q", hit, reason)
	}
}

func TestHeaderContainsMatcher_Miss(t *testing.T) {
	m := &HeaderContainsMatcher{Name: "Set-Cookie", Substring: "pwn=1"}
	resp := &http.Response{Header: http.Header{"Set-Cookie": []string{"session=abc"}}}
	hit, _ := m.Match(resp, nil)
	if hit {
		t.Fatalf("expected miss")
	}
}

func TestHeaderContainsMatcher_NilResp(t *testing.T) {
	m := &HeaderContainsMatcher{Name: "X", Substring: "y"}
	hit, _ := m.Match(nil, nil)
	if hit {
		t.Fatalf("expected miss on nil response")
	}
}
```

- [ ] **Step 2: Run + commit**

```
go test ./internal/dast/... -run TestHeaderContainsMatcher -v 2>&1 | tail -5
git add internal/dast/matchers_test.go
git commit -m "test(dast): cover HeaderContainsMatcher hit/miss/nil cases"
git push
```

Expected: PASS, then commit message printed.

### Task D1.3: HeaderRegexMatcher + StatusDiffMatcher tests

**Files:**
- Modify: `internal/dast/matchers_test.go`

- [ ] **Step 1: Append tests**

```go
func TestHeaderRegexMatcher_Hit(t *testing.T) {
	m := &HeaderRegexMatcher{
		Name:    "Location",
		Pattern: regexp.MustCompile(`https?://(evil|example)\.org`),
		Reason:  "open redirect",
	}
	resp := &http.Response{Header: http.Header{"Location": []string{"https://example.org/x"}}}
	hit, reason := m.Match(resp, nil)
	if !hit || reason != "open redirect" {
		t.Fatalf("hit=%v reason=%q", hit, reason)
	}
}

func TestHeaderRegexMatcher_Miss(t *testing.T) {
	m := &HeaderRegexMatcher{Name: "Location", Pattern: regexp.MustCompile(`evil`)}
	resp := &http.Response{Header: http.Header{"Location": []string{"/internal/path"}}}
	hit, _ := m.Match(resp, nil)
	if hit {
		t.Fatalf("expected miss")
	}
}

func TestStatusDiffMatcher_HitWhenBaselineDiffers(t *testing.T) {
	m := &StatusDiffMatcher{BaselineCode: 401, ProbeCode: 200, Reason: "auth bypass"}
	resp := &http.Response{StatusCode: 200}
	hit, reason := m.Match(resp, nil)
	if !hit || reason != "auth bypass" {
		t.Fatalf("hit=%v reason=%q", hit, reason)
	}
}

func TestStatusDiffMatcher_MissWhenSameAsBaseline(t *testing.T) {
	m := &StatusDiffMatcher{BaselineCode: 200, ProbeCode: 200}
	resp := &http.Response{StatusCode: 200}
	hit, _ := m.Match(resp, nil)
	if hit {
		t.Fatalf("expected miss when probe matches baseline")
	}
}

func TestStatusDiffMatcher_HitWithoutBaseline(t *testing.T) {
	// No baseline configured (zero value) → fire on ProbeCode alone
	m := &StatusDiffMatcher{ProbeCode: 200, Reason: "static probe"}
	resp := &http.Response{StatusCode: 200}
	hit, _ := m.Match(resp, nil)
	if !hit {
		t.Fatalf("expected hit when baseline is zero and probe matches")
	}
}
```

- [ ] **Step 2: Run + commit**

```
go test ./internal/dast/... -run "TestHeaderRegexMatcher|TestStatusDiffMatcher" -v 2>&1 | tail -10
git add internal/dast/matchers_test.go
git commit -m "test(dast): cover HeaderRegexMatcher + StatusDiffMatcher matchers"
git push
```

Expected: 5 PASS lines.

### Task D1.4: Add `MinProfile` to TestCase + `CapturedJWT` to Endpoint

**Files:**
- Modify: `internal/dast/testcase.go`
- Modify: `internal/dast/generator.go`

- [ ] **Step 1: Read existing TestCase struct**

```
grep -n "type TestCase struct" internal/dast/testcase.go
sed -n '12,30p' internal/dast/testcase.go
```

Expected: lines 12-25 show the existing struct.

- [ ] **Step 2: Add `MinProfile` field**

In `internal/dast/testcase.go`, find the `TestCase` struct and append a new field at the end (before the `Matcher` field, since `Matcher` is the last and has the `json:"-"` tag — keep it last). The struct must look like:
```go
type TestCase struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Confidence  string            `json:"confidence"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`

	// MinProfile is the minimum scan profile required for this test case
	// to run. Empty value means "standard" (the existing default).
	// Valid values: "passive", "standard", "aggressive".
	MinProfile string `json:"min_profile,omitempty"`

	Matcher ResponseMatcher `json:"-"`
}
```

- [ ] **Step 3: Add `CapturedJWT` to Endpoint**

In `internal/dast/generator.go`, find the `Endpoint` struct (lines 9-15) and append a field:
```go
type Endpoint struct {
	Path        string
	Method      string
	Parameters  []Parameter
	RequestBody *RequestBodySpec
	BaseURL     string
	// CapturedJWT, when non-empty, is a JWT (compact serialization) that
	// the orchestrator captured from this endpoint's auth profile during
	// baseline crawl. Used by JWT-targeted probes. Empty means no JWT
	// was observed; JWT probes skip the endpoint silently.
	CapturedJWT string
}
```

- [ ] **Step 4: Verify build still passes**

```
go build ./internal/dast/... 2>&1 | tail -3
go test ./internal/dast/... 2>&1 | tail -3
```

Expected: build clean, tests PASS.

- [ ] **Step 5: Commit + push**

```
git add internal/dast/testcase.go internal/dast/generator.go
git commit -m "feat(dast): add TestCase.MinProfile and Endpoint.CapturedJWT fields"
git push
```

### Task D1.5: Add `Profile` to ScanJob + plumb to GenerateTestCases

**Files:**
- Modify: `internal/dast/worker.go`
- Modify: `internal/dast/generator.go`

- [ ] **Step 1: Add `Profile` field to ScanJob**

In `internal/dast/worker.go`, find the `ScanJob` struct (around line 108-118) and add a field:
```go
type ScanJob struct {
	ID            string     `json:"id"`
	TargetBaseURL string     `json:"target_base_url"`
	AllowedHosts  []string   `json:"allowed_hosts"`
	PinnedIPs     []string   `json:"pinned_ips"`
	Endpoints     []Endpoint `json:"endpoints"`
	AuthConfig    *authbroker.AuthConfig `json:"auth_config,omitempty"`
	ScopeConfig   scope.Config `json:"-"`
	Concurrency   int        `json:"concurrency"`
	RequestDelay  time.Duration `json:"request_delay"`

	// Profile is the scan profile ("passive", "standard", "aggressive").
	// Determines which probes run. Empty defaults to "standard".
	Profile string `json:"profile,omitempty"`
}
```

- [ ] **Step 2: Update GenerateTestCases signature + call site**

In `internal/dast/generator.go`, change the `GenerateTestCases` function signature:

Replace:
```go
func GenerateTestCases(endpoints []Endpoint) []TestCase {
	var cases []TestCase

	for _, ep := range endpoints {
		fullURL := ep.BaseURL + ep.Path
		cases = append(cases, generateSQLiTests(ep, fullURL)...)
		cases = append(cases, generateXSSTests(ep, fullURL)...)
		cases = append(cases, generatePathTraversalTests(ep, fullURL)...)
		cases = append(cases, generateSSRFTests(ep, fullURL)...)
		cases = append(cases, generateIDORTests(ep, fullURL)...)
		cases = append(cases, generateHeaderInjectionTests(ep, fullURL)...)
	}

	return cases
}
```

With:
```go
// profileRank ranks scan profiles for filtering. Higher = more permissive.
var profileRank = map[string]int{
	"passive":    0,
	"standard":   1,
	"aggressive": 2,
}

// GenerateTestCases creates DAST test cases for a set of API endpoints.
// `profile` is the scan profile ("passive", "standard", "aggressive");
// empty string defaults to "standard". Test cases whose MinProfile rank
// exceeds the requested profile are dropped.
func GenerateTestCases(endpoints []Endpoint, profile string) []TestCase {
	if profile == "" {
		profile = "standard"
	}
	requested, ok := profileRank[profile]
	if !ok {
		requested = profileRank["standard"]
	}

	var cases []TestCase
	for _, ep := range endpoints {
		fullURL := ep.BaseURL + ep.Path
		cases = append(cases, generateSQLiTests(ep, fullURL)...)
		cases = append(cases, generateXSSTests(ep, fullURL)...)
		cases = append(cases, generatePathTraversalTests(ep, fullURL)...)
		cases = append(cases, generateSSRFTests(ep, fullURL)...)
		cases = append(cases, generateIDORTests(ep, fullURL)...)
		cases = append(cases, generateHeaderInjectionTests(ep, fullURL)...)
	}

	// Filter by profile.
	filtered := cases[:0]
	for _, tc := range cases {
		min := tc.MinProfile
		if min == "" {
			min = "standard"
		}
		minRank, ok := profileRank[min]
		if !ok {
			minRank = profileRank["standard"]
		}
		if minRank <= requested {
			filtered = append(filtered, tc)
		}
	}
	return filtered
}
```

- [ ] **Step 3: Update worker call site**

In `internal/dast/worker.go`, find the `GenerateTestCases(job.Endpoints)` call and replace with:
```go
testCases := GenerateTestCases(job.Endpoints, job.Profile)
```

- [ ] **Step 4: Update existing tests in `generator_test.go`**

`internal/dast/generator_test.go` calls `GenerateTestCases(endpoints)` (5 places — search and replace). Update each to `GenerateTestCases(endpoints, "standard")`. Run:
```
sed -i.bak 's/GenerateTestCases(endpoints)/GenerateTestCases(endpoints, "standard")/g' internal/dast/generator_test.go
rm internal/dast/generator_test.go.bak
```

- [ ] **Step 5: Verify**

```
go build ./internal/dast/... 2>&1 | tail -3
go test ./internal/dast/... 2>&1 | tail -3
```

Expected: build clean, all tests PASS (existing 6 probe tests still pass through the filter at default profile).

- [ ] **Step 6: Commit + push**

```
git add internal/dast/worker.go internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): plumb scan profile through GenerateTestCases with filter logic"
git push
```

### Task D1.6: PR D1 build, deploy, smoke

- [ ] **Step 1: Sync source to server**

```
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-probes/
rsync -az --delete --exclude .git --exclude .next --exclude node_modules --exclude .worktrees --exclude '*.test' \
  ./ okyay@77.42.34.174:/tmp/sentinelcore-src/
```

- [ ] **Step 2: Build dast-worker image**

```
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build --build-arg SERVICE=dast-worker -t sentinelcore/dast-worker:dast-pr1 . 2>&1 | tail -8"
```

Expected: build success.

- [ ] **Step 3: Deploy + verify**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/dast-worker:dast-pr1 sentinelcore/dast-worker:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d dast-worker 2>&1 | tail -3 && \
  sleep 2 && docker ps --filter name=dast --format '{{.Names}}: {{.Status}}'"
curl -s -o /dev/null -w 'healthz: %{http_code}\nreadyz: %{http_code}\n' https://sentinelcore.resiliencetech.com.tr/healthz
```

Expected: dast-worker container Up; both endpoints 200.

PR D1 complete. Existing DAST behavior unchanged; new matchers and fields are present but unused until PR D2.

---

## PR D2 — Nine probe generators

Each task adds one probe-generator function plus its unit test, calls it from `GenerateTestCases`, and commits + pushes. The integration tests (Task D2.10) and the profile-gating test (Task D2.11) come at the end.

### Task D2.1: XXE probe generator

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append failing test**

Add to `internal/dast/generator_test.go`:
```go
func TestGenerateTestCases_XXE(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/parse",
			Method:  "POST",
			BaseURL: "http://target.local",
			RequestBody: &RequestBodySpec{
				ContentType: "application/xml",
			},
		},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var xxe []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-XXE-001" {
			xxe = append(xxe, c)
		}
	}
	if len(xxe) == 0 {
		t.Fatalf("expected at least 1 XXE test case, got 0")
	}
	if xxe[0].Category != "xxe" {
		t.Errorf("category = %q, want xxe", xxe[0].Category)
	}
	if xxe[0].Severity != "high" {
		t.Errorf("severity = %q, want high", xxe[0].Severity)
	}
	if xxe[0].ContentType != "application/xml" {
		t.Errorf("content_type = %q, want application/xml", xxe[0].ContentType)
	}
	if !strings.Contains(xxe[0].Body, "ENTITY") {
		t.Errorf("body should contain ENTITY declaration, got %q", xxe[0].Body)
	}
}
```

If `internal/dast/generator_test.go` doesn't already import `strings`, add it.

- [ ] **Step 2: Run test (FAIL — DAST-XXE-001 not emitted)**

```
go test ./internal/dast/... -run TestGenerateTestCases_XXE -v 2>&1 | tail -5
```

Expected: FAIL with "expected at least 1 XXE test case, got 0".

- [ ] **Step 3: Add XXE generator to `generator.go`**

Append after the existing `generateHeaderInjectionTests` function:
```go
// generateXXETests probes endpoints accepting XML bodies for external-entity
// expansion. Payload includes a SYSTEM entity that resolves /etc/passwd; the
// matcher fires on a /etc/passwd-shaped response body.
func generateXXETests(ep Endpoint, baseURL string) []TestCase {
	if ep.RequestBody == nil ||
		!strings.Contains(strings.ToLower(ep.RequestBody.ContentType), "xml") {
		return nil
	}
	payload := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
		`<root>&xxe;</root>`
	return []TestCase{{
		ID:          fmt.Sprintf("xxe-%s", ep.Method),
		RuleID:      "DAST-XXE-001",
		Name:        "XXE via SYSTEM entity in XML body",
		Category:    "xxe",
		Severity:    "high",
		Confidence:  "medium",
		Method:      ep.Method,
		URL:         baseURL,
		ContentType: "application/xml",
		Body:        payload,
		MinProfile:  "standard",
		Matcher: &BodyRegexMatcher{
			Pattern: regexp.MustCompile(`root:[^:]*:0:0:`),
			Reason:  "external entity resolved /etc/passwd",
		},
	}}
}
```

If the file doesn't already import `regexp`, add it: `"regexp"` in the import block.

- [ ] **Step 4: Wire XXE into the aggregator**

In `GenerateTestCases`, add the call inside the per-endpoint loop:
```go
cases = append(cases, generateXXETests(ep, fullURL)...)
```

Place it right after the `generateHeaderInjectionTests` line.

- [ ] **Step 5: Verify test passes**

```
go test ./internal/dast/... -run TestGenerateTestCases_XXE -v 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 6: Commit + push**

```
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-XXE-001 probe — XML external-entity body injection"
git push
```

### Task D2.2: NoSQL injection probe

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append failing test**

```go
func TestGenerateTestCases_NoSQL(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/login",
			Method:  "POST",
			BaseURL: "http://target.local",
			RequestBody: &RequestBodySpec{
				ContentType: "application/json",
				Schema: map[string]string{
					"username": "string",
					"password": "string",
				},
			},
		},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var nosql []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-NOSQL-001" {
			nosql = append(nosql, c)
		}
	}
	if len(nosql) == 0 {
		t.Fatalf("expected at least 1 NoSQL test case, got 0")
	}
	if !strings.Contains(nosql[0].Body, "$ne") && !strings.Contains(nosql[0].Body, "$gt") {
		t.Errorf("expected $ne or $gt operator in body, got %q", nosql[0].Body)
	}
}
```

- [ ] **Step 2: Run (expect FAIL)**

```
go test ./internal/dast/... -run TestGenerateTestCases_NoSQL -v 2>&1 | tail -5
```

- [ ] **Step 3: Add generator**

Append:
```go
// generateNoSQLITests probes JSON-bodied endpoints for NoSQL-operator injection.
// Substitutes operator objects into expected string fields and looks for a
// status code that signals authentication or authorization bypass.
func generateNoSQLITests(ep Endpoint, baseURL string) []TestCase {
	if ep.RequestBody == nil ||
		!strings.Contains(strings.ToLower(ep.RequestBody.ContentType), "json") ||
		ep.RequestBody.Schema == nil {
		return nil
	}
	operators := []string{
		`{"$ne": null}`,
		`{"$gt": ""}`,
		`{"$regex": ".*"}`,
	}
	var cases []TestCase
	for fieldName := range ep.RequestBody.Schema {
		for i, op := range operators {
			body := buildJSONWithOperator(ep.RequestBody.Schema, fieldName, op)
			cases = append(cases, TestCase{
				ID:          fmt.Sprintf("nosql-%s-%s-%d", ep.Method, fieldName, i),
				RuleID:      "DAST-NOSQL-001",
				Name:        fmt.Sprintf("NoSQL operator injection via field %q", fieldName),
				Category:    "nosql_injection",
				Severity:    "high",
				Confidence:  "low",
				Method:      ep.Method,
				URL:         baseURL,
				ContentType: "application/json",
				Body:        body,
				MinProfile:  "standard",
				Matcher: &StatusCodeMatcher{
					// 200 on a typical login endpoint = bypass; baseline diff
					// would refine this in a future iteration.
					Codes: []int{200},
				},
			})
		}
	}
	return cases
}

// buildJSONWithOperator constructs a JSON body where one field is replaced by
// a raw operator JSON snippet. Other fields get a placeholder string value.
func buildJSONWithOperator(schema map[string]string, target, opJSON string) string {
	var parts []string
	for k := range schema {
		if k == target {
			parts = append(parts, fmt.Sprintf(`%q: %s`, k, opJSON))
		} else {
			parts = append(parts, fmt.Sprintf(`%q: "probe"`, k))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
```

Add `cases = append(cases, generateNoSQLITests(ep, fullURL)...)` to the aggregator after the XXE call.

- [ ] **Step 4: Verify**

```
go test ./internal/dast/... -run TestGenerateTestCases_NoSQL -v 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 5: Commit + push**

```
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-NOSQL-001 probe — operator-object injection in JSON bodies"
git push
```

### Task D2.3: GraphQL introspection probe

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append test**

```go
func TestGenerateTestCases_GraphQLIntrospection(t *testing.T) {
	endpoints := []Endpoint{
		{Path: "/graphql", Method: "POST", BaseURL: "http://target.local"},
	}
	cases := GenerateTestCases(endpoints, "passive")
	var gql []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-GRAPHQL-001" {
			gql = append(gql, c)
		}
	}
	if len(gql) == 0 {
		t.Fatalf("expected GraphQL probe, got 0")
	}
	if gql[0].MinProfile != "passive" {
		t.Errorf("min_profile = %q, want passive", gql[0].MinProfile)
	}
	if !strings.Contains(gql[0].Body, "__schema") {
		t.Errorf("body should contain __schema, got %q", gql[0].Body)
	}
}
```

- [ ] **Step 2: Run (FAIL)**

```
go test ./internal/dast/... -run TestGenerateTestCases_GraphQLIntrospection -v 2>&1 | tail -5
```

- [ ] **Step 3: Add generator**

```go
// generateGraphQLIntrospectionTests probes well-known GraphQL paths for an
// introspection-enabled endpoint. Sends an introspection query; the matcher
// fires when the response body advertises the schema.
func generateGraphQLIntrospectionTests(ep Endpoint, _ string) []TestCase {
	candidates := []string{"/graphql", "/api/graphql", "/v1/graphql"}
	matched := false
	for _, c := range candidates {
		if ep.Path == c {
			matched = true
			break
		}
	}
	if !matched {
		return nil
	}
	body := `{"query":"{__schema{types{name}}}"}`
	return []TestCase{{
		ID:          fmt.Sprintf("graphql-%s", ep.Method),
		RuleID:      "DAST-GRAPHQL-001",
		Name:        "GraphQL introspection enabled",
		Category:    "graphql_introspection",
		Severity:    "medium",
		Confidence:  "high",
		Method:      "POST",
		URL:         ep.BaseURL + ep.Path,
		ContentType: "application/json",
		Body:        body,
		MinProfile:  "passive",
		Matcher: &CompositeMatcher{
			Mode: "and",
			Matchers: []ResponseMatcher{
				&StatusCodeMatcher{Codes: []int{200}},
				&BodyContainsMatcher{Patterns: []string{`"__schema"`, `"types"`}},
			},
		},
	}}
}
```

Wire into aggregator: `cases = append(cases, generateGraphQLIntrospectionTests(ep, fullURL)...)`.

- [ ] **Step 4: Verify + commit**

```
go test ./internal/dast/... -run TestGenerateTestCases_GraphQLIntrospection -v 2>&1 | tail -5
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-GRAPHQL-001 probe — introspection enabled detector"
git push
```

### Task D2.4: JWT alg=none probe

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append test**

```go
func TestGenerateTestCases_JWTAlgNone(t *testing.T) {
	// Real-shaped HS256 token; payload contains no sensitive data.
	// Header decodes to: {"alg":"HS256","typ":"JWT"}
	// Payload decodes to: {"sub":"u","exp":99999999999}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1IiwiZXhwIjo5OTk5OTk5OTk5OX0.signature"
	endpoints := []Endpoint{
		{Path: "/me", Method: "GET", BaseURL: "http://target.local", CapturedJWT: jwt},
	}
	cases := GenerateTestCases(endpoints, "passive")
	var hits []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-JWT-001" {
			hits = append(hits, c)
		}
	}
	if len(hits) == 0 {
		t.Fatalf("expected DAST-JWT-001 case, got 0")
	}
	auth := hits[0].Headers["Authorization"]
	if !strings.HasPrefix(auth, "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.") {
		t.Errorf("Authorization header should carry an alg=none token, got %q", auth)
	}
	// Token must have empty signature (the trailing 3rd segment).
	if strings.HasSuffix(strings.TrimPrefix(auth, "Bearer "), ".signature") {
		t.Errorf("signature segment should be empty, got %q", auth)
	}
}

func TestGenerateTestCases_JWTAlgNone_NoTokenSkipped(t *testing.T) {
	endpoints := []Endpoint{
		{Path: "/me", Method: "GET", BaseURL: "http://target.local"},
	}
	cases := GenerateTestCases(endpoints, "passive")
	for _, c := range cases {
		if c.RuleID == "DAST-JWT-001" {
			t.Fatalf("expected JWT-001 to be skipped without CapturedJWT, but got %d cases", len(cases))
		}
	}
}
```

- [ ] **Step 2: Run (FAIL)**

```
go test ./internal/dast/... -run TestGenerateTestCases_JWTAlgNone -v 2>&1 | tail -10
```

- [ ] **Step 3: Add generator**

```go
// generateJWTAlgNoneTests re-signs a captured JWT with alg=none and an empty
// signature. The matcher fires when the modified token is accepted (probe
// returns 200 instead of the expected 401/403).
func generateJWTAlgNoneTests(ep Endpoint, baseURL string) []TestCase {
	if ep.CapturedJWT == "" {
		return nil
	}
	parts := strings.Split(ep.CapturedJWT, ".")
	if len(parts) != 3 {
		return nil
	}
	// Build header {"alg":"none","typ":"JWT"} as base64url (no padding).
	const noneHeaderB64 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	noneToken := noneHeaderB64 + "." + parts[1] + "."
	return []TestCase{{
		ID:         fmt.Sprintf("jwt-none-%s", ep.Method),
		RuleID:     "DAST-JWT-001",
		Name:       "JWT alg=none accepted",
		Category:   "jwt_alg_none",
		Severity:   "critical",
		Confidence: "high",
		Method:     ep.Method,
		URL:        baseURL,
		Headers:    map[string]string{"Authorization": "Bearer " + noneToken},
		MinProfile: "passive",
		Matcher: &StatusCodeMatcher{Codes: []int{200}},
	}}
}
```

Wire into aggregator.

- [ ] **Step 4: Verify + commit**

```
go test ./internal/dast/... -run TestGenerateTestCases_JWTAlgNone -v 2>&1 | tail -10
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-JWT-001 probe — JWT alg=none acceptance detector"
git push
```

### Task D2.5: JWT weak-secret probe

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append test**

```go
func TestGenerateTestCases_JWTWeakSecret(t *testing.T) {
	// Token signed with HS256 secret "secret":
	// header = {"alg":"HS256","typ":"JWT"}, payload = {"sub":"u"}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1In0.HrYpNiCfH_pBSYQ4G-bDzHOhx2eZ4q39oS24a3Y_uwQ"
	endpoints := []Endpoint{
		{Path: "/me", Method: "GET", BaseURL: "http://target.local", CapturedJWT: jwt},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var hit *TestCase
	for i, c := range cases {
		if c.RuleID == "DAST-JWT-002" {
			hit = &cases[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected DAST-JWT-002, got 0 cases")
	}
	if !strings.Contains(hit.Name, "secret") {
		t.Errorf("name should mention the cracked secret: %q", hit.Name)
	}
	if hit.MinProfile != "standard" {
		t.Errorf("min_profile = %q, want standard", hit.MinProfile)
	}
}
```

- [ ] **Step 2: Run (FAIL)**

```
go test ./internal/dast/... -run TestGenerateTestCases_JWTWeakSecret -v 2>&1 | tail -5
```

- [ ] **Step 3: Add generator + helpers**

Append:
```go
// jwtWeakSecretCandidates is the small dictionary that the weak-secret probe
// brute-forces against captured HS256 tokens. Twelve entries — enough to
// catch the most common copy-paste secrets; a longer list would inflate the
// per-endpoint test count without much marginal coverage.
var jwtWeakSecretCandidates = []string{
	"secret", "key", "password", "123456", "admin", "jwt",
	"JWT", "your-256-bit-secret", "please-change-me", "s3cr3t", "", "secretkey",
}

// generateJWTWeakSecretTests cracks the captured token offline against the
// dictionary above. If a candidate verifies the HS256 signature, the probe
// emits a single TestCase that re-uses the original token with that secret —
// the active probe is just hitting the endpoint with the same token to flag
// the finding (the cracked secret is the actual evidence and lives in the
// finding's name/description).
func generateJWTWeakSecretTests(ep Endpoint, baseURL string) []TestCase {
	if ep.CapturedJWT == "" {
		return nil
	}
	parts := strings.Split(ep.CapturedJWT, ".")
	if len(parts) != 3 {
		return nil
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	if !strings.Contains(string(headerJSON), `"HS256"`) {
		return nil
	}
	signedInput := []byte(parts[0] + "." + parts[1])
	expected, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil
	}
	for _, secret := range jwtWeakSecretCandidates {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(signedInput)
		if hmac.Equal(mac.Sum(nil), expected) {
			return []TestCase{{
				ID:         fmt.Sprintf("jwt-weak-%s", ep.Method),
				RuleID:     "DAST-JWT-002",
				Name:       fmt.Sprintf("JWT signed with weak secret %q", secret),
				Category:   "jwt_weak_secret",
				Severity:   "high",
				Confidence: "high",
				Method:     ep.Method,
				URL:        baseURL,
				Headers:    map[string]string{"Authorization": "Bearer " + ep.CapturedJWT},
				MinProfile: "standard",
				Matcher:    &StatusCodeMatcher{Codes: []int{200}},
			}}
		}
	}
	return nil
}
```

Add imports to `generator.go`:
```go
"crypto/hmac"
"crypto/sha256"
"encoding/base64"
```

Wire into aggregator.

- [ ] **Step 4: Verify + commit**

```
go test ./internal/dast/... -run TestGenerateTestCases_JWTWeakSecret -v 2>&1 | tail -5
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-JWT-002 probe — HS256 weak-secret offline brute"
git push
```

### Task D2.6: CRLF injection probe

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append test**

```go
func TestGenerateTestCases_CRLF(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/track",
			Method:  "GET",
			BaseURL: "http://target.local",
			Parameters: []Parameter{
				{Name: "id", In: "query", Type: "string"},
			},
		},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var crlf []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-CRLF-001" {
			crlf = append(crlf, c)
		}
	}
	if len(crlf) == 0 {
		t.Fatalf("expected CRLF probe, got 0")
	}
	if !strings.Contains(crlf[0].URL, "%0d%0a") && !strings.Contains(crlf[0].URL, "%0D%0A") {
		t.Errorf("URL should encode CR/LF, got %q", crlf[0].URL)
	}
}
```

- [ ] **Step 2: Run (FAIL)**

```
go test ./internal/dast/... -run TestGenerateTestCases_CRLF -v 2>&1 | tail -5
```

- [ ] **Step 3: Add generator**

```go
// generateCRLFTests injects %0d%0a-encoded CR/LF into query parameters and
// expects the response to echo a forged Set-Cookie header.
func generateCRLFTests(ep Endpoint, baseURL string) []TestCase {
	payloads := []string{
		"%0d%0aSet-Cookie:%20pwn=1",
		"%0D%0ASet-Cookie:%20pwn=1",
		"\r\nSet-Cookie: pwn=1",
	}
	var cases []TestCase
	for _, param := range ep.Parameters {
		if param.In != "query" && param.In != "path" {
			continue
		}
		for i, payload := range payloads {
			testURL := injectParam(baseURL, param, payload)
			cases = append(cases, TestCase{
				ID:         fmt.Sprintf("crlf-%s-%s-%d", ep.Method, param.Name, i),
				RuleID:     "DAST-CRLF-001",
				Name:       fmt.Sprintf("CRLF injection via %s param %q", param.In, param.Name),
				Category:   "crlf_injection",
				Severity:   "high",
				Confidence: "medium",
				Method:     ep.Method,
				URL:        testURL,
				MinProfile: "standard",
				Matcher: &HeaderContainsMatcher{
					Name:      "Set-Cookie",
					Substring: "pwn=1",
					Reason:    "injected Set-Cookie header echoed in response",
				},
			})
		}
	}
	return cases
}
```

Wire into aggregator.

- [ ] **Step 4: Verify + commit**

```
go test ./internal/dast/... -run TestGenerateTestCases_CRLF -v 2>&1 | tail -5
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-CRLF-001 probe — CRLF injection via query/path params"
git push
```

### Task D2.7: Open redirect probe

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append test**

```go
func TestGenerateTestCases_OpenRedirect(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/login/callback",
			Method:  "GET",
			BaseURL: "http://target.local",
			Parameters: []Parameter{
				{Name: "next", In: "query", Type: "string"},
				{Name: "id", In: "query", Type: "integer"},
			},
		},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var redirs []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-OPENREDIR-001" {
			redirs = append(redirs, c)
		}
	}
	if len(redirs) == 0 {
		t.Fatalf("expected open-redirect probes, got 0")
	}
	// Should target the "next" param, not "id"
	for _, c := range redirs {
		if !strings.Contains(c.URL, "next=") {
			t.Errorf("probe should target the redirect-shaped param, got URL %q", c.URL)
		}
	}
}
```

- [ ] **Step 2: Run (FAIL)**

```
go test ./internal/dast/... -run TestGenerateTestCases_OpenRedirect -v 2>&1 | tail -5
```

- [ ] **Step 3: Add generator**

```go
// redirectParamNames lists query parameters commonly used to encode the next
// URL after a redirect. The probe only fires when one of these is present.
var redirectParamNames = map[string]bool{
	"redirect": true, "next": true, "url": true,
	"return": true, "returnurl": true, "goto": true, "to": true,
}

// generateOpenRedirectTests injects external URLs into redirect-shaped
// parameters and expects the response Location header to echo the injected
// origin.
func generateOpenRedirectTests(ep Endpoint, baseURL string) []TestCase {
	payloads := []string{
		"https://example.org/sentinel-probe",
		"//example.org/sentinel-probe",
	}
	var cases []TestCase
	for _, param := range ep.Parameters {
		if param.In != "query" {
			continue
		}
		if !redirectParamNames[strings.ToLower(param.Name)] {
			continue
		}
		for i, payload := range payloads {
			testURL := injectParam(baseURL, param, payload)
			cases = append(cases, TestCase{
				ID:         fmt.Sprintf("openredir-%s-%s-%d", ep.Method, param.Name, i),
				RuleID:     "DAST-OPENREDIR-001",
				Name:       fmt.Sprintf("Open redirect via %s param %q", param.In, param.Name),
				Category:   "open_redirect",
				Severity:   "medium",
				Confidence: "high",
				Method:     ep.Method,
				URL:        testURL,
				MinProfile: "standard",
				Matcher: &HeaderRegexMatcher{
					Name:    "Location",
					Pattern: regexp.MustCompile(`(?:https?:)?//(?:[^/]*\.)?example\.org`),
					Reason:  "Location header echoes attacker-controlled origin",
				},
			})
		}
	}
	return cases
}
```

Wire into aggregator.

- [ ] **Step 4: Verify + commit**

```
go test ./internal/dast/... -run TestGenerateTestCases_OpenRedirect -v 2>&1 | tail -5
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-OPENREDIR-001 probe — active open-redirect detector"
git push
```

### Task D2.8: Mass assignment probe

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append test**

```go
func TestGenerateTestCases_MassAssignment(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/users",
			Method:  "POST",
			BaseURL: "http://target.local",
			RequestBody: &RequestBodySpec{
				ContentType: "application/json",
				Schema: map[string]string{
					"name":  "string",
					"email": "string",
				},
			},
		},
	}
	// Aggressive profile required.
	casesAggr := GenerateTestCases(endpoints, "aggressive")
	var hits []TestCase
	for _, c := range casesAggr {
		if c.RuleID == "DAST-MASS-001" {
			hits = append(hits, c)
		}
	}
	if len(hits) == 0 {
		t.Fatalf("expected mass-assignment probe at aggressive profile, got 0")
	}
	if !strings.Contains(hits[0].Body, "is_admin") {
		t.Errorf("body should include is_admin payload, got %q", hits[0].Body)
	}
	// Standard profile must NOT emit MASS probes.
	casesStd := GenerateTestCases(endpoints, "standard")
	for _, c := range casesStd {
		if c.RuleID == "DAST-MASS-001" {
			t.Fatalf("MASS probe should be gated to aggressive, but appeared in standard")
		}
	}
}
```

- [ ] **Step 2: Run (FAIL)**

```
go test ./internal/dast/... -run TestGenerateTestCases_MassAssignment -v 2>&1 | tail -5
```

- [ ] **Step 3: Add generator**

```go
// generateMassAssignmentTests posts a JSON body that includes the documented
// fields plus four privileged extras. The matcher fires when the response
// echoes any of the extras with the injected value (1-step detection — full
// 2-step verification with a follow-up read is a future enhancement).
func generateMassAssignmentTests(ep Endpoint, baseURL string) []TestCase {
	if ep.RequestBody == nil ||
		!strings.Contains(strings.ToLower(ep.RequestBody.ContentType), "json") ||
		ep.RequestBody.Schema == nil {
		return nil
	}
	if ep.Method != "POST" && ep.Method != "PUT" && ep.Method != "PATCH" {
		return nil
	}
	extras := map[string]string{
		"is_admin":  "true",
		"role":      `"admin"`,
		"verified":  "true",
		"balance":   "999999",
	}
	parts := []string{}
	for k := range ep.RequestBody.Schema {
		parts = append(parts, fmt.Sprintf(`%q: "probe"`, k))
	}
	for k, v := range extras {
		parts = append(parts, fmt.Sprintf(`%q: %s`, k, v))
	}
	body := "{" + strings.Join(parts, ", ") + "}"
	return []TestCase{{
		ID:          fmt.Sprintf("mass-%s", ep.Method),
		RuleID:      "DAST-MASS-001",
		Name:        "Mass assignment via privileged extra fields in JSON body",
		Category:    "mass_assignment",
		Severity:    "medium",
		Confidence:  "low",
		Method:      ep.Method,
		URL:         baseURL,
		ContentType: "application/json",
		Body:        body,
		MinProfile:  "aggressive",
		Matcher: &CompositeMatcher{
			Mode: "and",
			Matchers: []ResponseMatcher{
				&StatusCodeMatcher{Codes: []int{200, 201}},
				&BodyRegexMatcher{
					Pattern: regexp.MustCompile(`"(is_admin|role|verified|balance)"\s*:\s*(true|"admin"|999999)`),
					Reason:  "response echoes injected privileged field with the injected value",
				},
			},
		},
	}}
}
```

Wire into aggregator.

- [ ] **Step 4: Verify + commit**

```
go test ./internal/dast/... -run TestGenerateTestCases_MassAssignment -v 2>&1 | tail -5
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-MASS-001 probe — mass assignment via privileged extras"
git push
```

### Task D2.9: Prototype pollution probe

**Files:**
- Modify: `internal/dast/generator.go`
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append test**

```go
func TestGenerateTestCases_PrototypePollution(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/config",
			Method:  "POST",
			BaseURL: "http://target.local",
			RequestBody: &RequestBodySpec{
				ContentType: "application/json",
			},
		},
	}
	casesAggr := GenerateTestCases(endpoints, "aggressive")
	var hits []TestCase
	for _, c := range casesAggr {
		if c.RuleID == "DAST-PROTO-POL-001" {
			hits = append(hits, c)
		}
	}
	if len(hits) == 0 {
		t.Fatalf("expected proto-pollution probe at aggressive profile, got 0")
	}
	if !strings.Contains(hits[0].Body, "__proto__") {
		t.Errorf("body should include __proto__, got %q", hits[0].Body)
	}
	casesStd := GenerateTestCases(endpoints, "standard")
	for _, c := range casesStd {
		if c.RuleID == "DAST-PROTO-POL-001" {
			t.Fatalf("PROTO-POL probe should be gated to aggressive, but appeared in standard")
		}
	}
}
```

- [ ] **Step 2: Run (FAIL)**

```
go test ./internal/dast/... -run TestGenerateTestCases_PrototypePollution -v 2>&1 | tail -5
```

- [ ] **Step 3: Add generator**

```go
// generatePrototypePollutionTests posts a JSON body containing __proto__ /
// constructor.prototype keys with a unique sentinel value. The matcher fires
// when the response echoes the sentinel back, indicating the merge polluted
// a shared object that the response constructed.
func generatePrototypePollutionTests(ep Endpoint, baseURL string) []TestCase {
	if ep.RequestBody == nil ||
		!strings.Contains(strings.ToLower(ep.RequestBody.ContentType), "json") {
		return nil
	}
	if ep.Method != "POST" && ep.Method != "PUT" && ep.Method != "PATCH" {
		return nil
	}
	bodies := []string{
		`{"__proto__":{"sentinelProbe":"polluted"}}`,
		`{"constructor":{"prototype":{"sentinelProbe":"polluted"}}}`,
	}
	var cases []TestCase
	for i, body := range bodies {
		cases = append(cases, TestCase{
			ID:          fmt.Sprintf("proto-pol-%s-%d", ep.Method, i),
			RuleID:      "DAST-PROTO-POL-001",
			Name:        "Prototype pollution via JSON merge sink",
			Category:    "prototype_pollution",
			Severity:    "high",
			Confidence:  "low",
			Method:      ep.Method,
			URL:         baseURL,
			ContentType: "application/json",
			Body:        body,
			MinProfile:  "aggressive",
			Matcher: &BodyContainsMatcher{Patterns: []string{`"sentinelProbe":"polluted"`}},
		})
	}
	return cases
}
```

Wire into aggregator.

- [ ] **Step 4: Verify + commit**

```
go test ./internal/dast/... -run TestGenerateTestCases_PrototypePollution -v 2>&1 | tail -5
git add internal/dast/generator.go internal/dast/generator_test.go
git commit -m "feat(dast): DAST-PROTO-POL-001 probe — prototype pollution via JSON merge"
git push
```

### Task D2.10: Profile-gating regression test

**Files:**
- Modify: `internal/dast/generator_test.go`

- [ ] **Step 1: Append test**

```go
func TestGenerateTestCases_ProfileGating(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:        "/users",
			Method:      "POST",
			BaseURL:     "http://target.local",
			Parameters:  []Parameter{{Name: "id", In: "path", Type: "string"}},
			RequestBody: &RequestBodySpec{ContentType: "application/json", Schema: map[string]string{"name": "string"}},
			CapturedJWT: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1In0.HrYpNiCfH_pBSYQ4G-bDzHOhx2eZ4q39oS24a3Y_uwQ",
		},
		{
			Path:    "/graphql",
			Method:  "POST",
			BaseURL: "http://target.local",
		},
	}
	collect := func(profile string) map[string]int {
		buckets := map[string]int{}
		for _, c := range GenerateTestCases(endpoints, profile) {
			buckets[c.RuleID]++
		}
		return buckets
	}
	passive := collect("passive")
	for _, id := range []string{"DAST-GRAPHQL-001", "DAST-JWT-001"} {
		if passive[id] == 0 {
			t.Errorf("passive profile should include %s", id)
		}
	}
	for _, id := range []string{"DAST-MASS-001", "DAST-PROTO-POL-001", "DAST-XXE-001", "DAST-NOSQL-001"} {
		if passive[id] != 0 {
			t.Errorf("passive profile should NOT include %s", id)
		}
	}
	standard := collect("standard")
	for _, id := range []string{"DAST-MASS-001", "DAST-PROTO-POL-001"} {
		if standard[id] != 0 {
			t.Errorf("standard profile should NOT include %s", id)
		}
	}
	aggressive := collect("aggressive")
	for _, id := range []string{"DAST-MASS-001", "DAST-PROTO-POL-001", "DAST-XXE-001", "DAST-GRAPHQL-001"} {
		if aggressive[id] == 0 {
			t.Errorf("aggressive profile should include %s", id)
		}
	}
}
```

- [ ] **Step 2: Run + commit**

```
go test ./internal/dast/... -run TestGenerateTestCases_ProfileGating -v 2>&1 | tail -10
git add internal/dast/generator_test.go
git commit -m "test(dast): regression test for profile gating across 9 new probes"
git push
```

Expected: PASS.

### Task D2.11: Integration tests against httptest servers

**Files:**
- Modify: `internal/dast/integration_test.go`

- [ ] **Step 1: Read existing file**

```
cat internal/dast/integration_test.go | head -80
```

If the file doesn't exist or doesn't have a relevant skeleton, create it. The new tests should be in this file.

- [ ] **Step 2: Append three integration tests**

Add at the end of the file (or create the file with the package + imports if absent):
```go
package dast

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIntegration_XXE_FiresOnEchoedFileContents(t *testing.T) {
	// Server simulates a vulnerable XML parser that echoes resolved entities
	// back as part of the response body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "ENTITY") && strings.Contains(string(body), "&xxe;") {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	ep := Endpoint{
		Path:    "/parse",
		Method:  "POST",
		BaseURL: srv.URL,
		RequestBody: &RequestBodySpec{ContentType: "application/xml"},
	}
	cases := GenerateTestCases([]Endpoint{ep}, "standard")
	var xxe *TestCase
	for i, c := range cases {
		if c.RuleID == "DAST-XXE-001" {
			xxe = &cases[i]
			break
		}
	}
	if xxe == nil {
		t.Fatal("no XXE test case generated")
	}
	req, err := xxe.BuildRequest(context.Background())
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	hit, reason := xxe.Matcher.Match(resp, body)
	if !hit {
		t.Fatalf("matcher did not fire on echoed /etc/passwd; body=%q", body)
	}
	if !strings.Contains(reason, "external entity") {
		t.Errorf("unexpected reason %q", reason)
	}
}

func TestIntegration_JWTAlgNone_FiresOn200(t *testing.T) {
	// Vulnerable server: trusts alg=none.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing token", 401)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			http.Error(w, "bad token", 401)
			return
		}
		// Pretend the alg=none header is acceptable.
		header, _ := decodeJWTHeaderForTest(parts[0])
		if alg, ok := header["alg"]; ok && alg == "none" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("welcome"))
			return
		}
		http.Error(w, "unauthorised", 401)
	}))
	defer srv.Close()
	ep := Endpoint{
		Path:        "/me",
		Method:      "GET",
		BaseURL:     srv.URL,
		CapturedJWT: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1In0.AAAA",
	}
	cases := GenerateTestCases([]Endpoint{ep}, "passive")
	var probe *TestCase
	for i, c := range cases {
		if c.RuleID == "DAST-JWT-001" {
			probe = &cases[i]
			break
		}
	}
	if probe == nil {
		t.Fatal("no JWT alg=none probe generated")
	}
	req, _ := probe.BuildRequest(context.Background())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("vulnerable server should return 200; got %d", resp.StatusCode)
	}
	hit, _ := probe.Matcher.Match(resp, nil)
	if !hit {
		t.Fatalf("matcher did not fire on 200 response")
	}
}

func TestIntegration_PrototypePollution_FiresOnEchoedSentinel(t *testing.T) {
	// Vulnerable server: parses JSON and echoes a merged config that contains
	// the sentinel value when the request contained __proto__.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		// Simulate naive merge: copy proto fields into the response config.
		out := map[string]interface{}{"theme": "light"}
		if proto, ok := payload["__proto__"].(map[string]interface{}); ok {
			for k, v := range proto {
				out[k] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	ep := Endpoint{
		Path:    "/config",
		Method:  "POST",
		BaseURL: srv.URL,
		RequestBody: &RequestBodySpec{ContentType: "application/json"},
	}
	cases := GenerateTestCases([]Endpoint{ep}, "aggressive")
	var probe *TestCase
	for i, c := range cases {
		if c.RuleID == "DAST-PROTO-POL-001" {
			probe = &cases[i]
			break
		}
	}
	if probe == nil {
		t.Fatal("no proto-pollution probe generated")
	}
	req, _ := probe.BuildRequest(context.Background())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	hit, _ := probe.Matcher.Match(resp, body)
	if !hit {
		t.Fatalf("matcher did not fire on echoed sentinel; body=%q", body)
	}
}

// decodeJWTHeaderForTest is a tiny JSON+base64 helper used only by the
// JWT-alg-none integration test. Production probe code has its own.
func decodeJWTHeaderForTest(hdrB64 string) (map[string]string, error) {
	raw, err := base64URLDecode(hdrB64)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return decodeStdURLB64(s)
}
```

If the file already imports `"encoding/base64"`, you can replace `decodeStdURLB64` with `base64.URLEncoding.DecodeString`. Otherwise, add this helper at the bottom:
```go
// decodeStdURLB64 is the URL variant of base64 used by JWTs. Defined locally
// so the test stays single-file with explicit dependencies.
func decodeStdURLB64(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}
```

…and add `"encoding/base64"` to the import block.

- [ ] **Step 3: Run all integration tests**

```
go test ./internal/dast/... -run TestIntegration -v 2>&1 | tail -20
```

Expected: 3 PASS lines.

- [ ] **Step 4: Commit + push**

```
git add internal/dast/integration_test.go
git commit -m "test(dast): integration tests for XXE / JWT alg=none / prototype pollution"
git push
```

### Task D2.12: PR D2 build, deploy, smoke

- [ ] **Step 1: Run all DAST tests**

```
go test ./internal/dast/... 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 2: Sync, build, deploy**

```
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-probes/
rsync -az --delete --exclude .git --exclude .next --exclude node_modules --exclude .worktrees --exclude '*.test' \
  ./ okyay@77.42.34.174:/tmp/sentinelcore-src/
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build --build-arg SERVICE=dast-worker -t sentinelcore/dast-worker:dast-pr2 . 2>&1 | tail -5 && \
  docker tag sentinelcore/dast-worker:dast-pr2 sentinelcore/dast-worker:pilot && \
  docker tag sentinelcore/dast-worker:dast-pr2 sentinelcore/dast-worker:dast-final && \
  cd /opt/sentinelcore/compose && docker compose up -d dast-worker"
sleep 3
ssh okyay@77.42.34.174 "docker logs --tail 30 sentinelcore_dast_worker 2>&1 | tail -20"
```

Expected: build success, dast-worker container starts cleanly. Logs should show worker startup with no panic.

- [ ] **Step 3: Open PR**

```
gh pr create --title "feat(dast): add 9 active probes + 4 matchers + profile gating" --body "$(cat <<'EOF'
## Summary
- Lifts active DAST coverage from 6 probes to 15. New probe IDs:
  DAST-XXE-001, DAST-NOSQL-001, DAST-GRAPHQL-001, DAST-JWT-001, DAST-JWT-002,
  DAST-CRLF-001, DAST-OPENREDIR-001, DAST-MASS-001, DAST-PROTO-POL-001.
- Adds four new response matchers (BodyRegex, HeaderContains, HeaderRegex,
  StatusDiff) and a `MinProfile` field on TestCase so destructive probes
  (MASS, PROTO-POL) are gated behind the `aggressive` scan profile.
- Plumbs `scan_profile` from ScanJob through GenerateTestCases.

## PR sequence
- **PR D1** — matchers + Endpoint.CapturedJWT + TestCase.MinProfile + scan-profile plumbing.
- **PR D2** — 9 probe generators + integration tests + profile-gating regression test.

## Test plan
- [x] go test ./internal/dast/... PASS
- [x] dast-worker:dast-pr2 image builds cleanly
- [x] worker starts without panic on the deployed image

## Rollback
- `sentinelcore/dast-worker:pilot-pre-dast-expansion` retained for one-command rollback.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

PR opens; smoke test complete.

---

## Self-review

### Spec coverage

| Spec section | Implementing task(s) |
|--------------|----------------------|
| §3.1 Profile gating | D1.5 (plumbing), D2.10 (regression test) |
| §3.2 Auth-aware probes (CapturedJWT) | D1.4 (field), D2.4 + D2.5 (consumers) |
| §3 Probes (1–9) | D2.1–D2.9 |
| §4 New matchers | D1.1 (impl), D1.2–D1.3 (tests) |
| §5 File structure | All file paths in tasks match spec |
| §6 Implementation strategy (PR D1, PR D2) | PR D1 = D1.1–D1.6; PR D2 = D2.1–D2.12 |
| §7.1 Unit tests | One per probe in D2.1–D2.9 |
| §7.2 Integration tests | D2.11 (XXE, JWT alg=none, prototype pollution) |
| §7.3 Profile gating test | D2.10 |
| §8 Risks / mitigations | Profile gating implements aggressive-only for state-mutating; JWT skip note in D2.4 |

No spec gap.

### Placeholder scan

Searched for "TBD", "TODO", "implement later", "fill in details", "Add appropriate error handling", "Similar to Task" — none present. Every code step has a complete code block or a precise sed/find command.

### Type consistency

- `TestCase.MinProfile string` — defined in D1.4, set in D2.1–D2.9, read by `GenerateTestCases` filter in D1.5. All sites use the literal strings `"passive"`, `"standard"`, `"aggressive"`.
- `Endpoint.CapturedJWT string` — defined in D1.4, read in D2.4 and D2.5.
- `ScanJob.Profile string` — defined in D1.5, passed to `GenerateTestCases(job.Endpoints, job.Profile)` in the worker call site (D1.5 step 3).
- `BodyRegexMatcher`, `HeaderContainsMatcher`, `HeaderRegexMatcher`, `StatusDiffMatcher` — defined in D1.1, used in D2.1 (BodyRegex), D2.6 (HeaderContains), D2.7 (HeaderRegex). `StatusDiffMatcher` is reserved for future use; not consumed by any of the 9 new probes here, but tested in D1.3.

No drift.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-01-dast-probe-expansion.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task; review between PRs.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch with checkpoints.

Which approach?
