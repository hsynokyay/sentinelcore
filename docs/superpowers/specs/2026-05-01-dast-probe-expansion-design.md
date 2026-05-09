# DAST Active Probe Expansion — Design Spec

**Status:** Design complete, awaiting implementation plan
**Owner:** Huseyin
**Target:** `internal/dast/` — add 9 active probe types and 4 new response matchers, lifting active DAST coverage from 6 probes to 15
**Date:** 2026-05-01

---

## 1. Goals & non-goals

### Goals

- Expand DAST active probe coverage from 6 (SQLi, XSS, PT, SSRF, IDOR, HI) to 15 by adding 9 new probe types: XXE, NoSQL injection, GraphQL introspection, JWT alg=none, JWT weak secret, CRLF injection, open redirect, mass assignment, prototype pollution.
- Add four new response matchers (`BodyRegexMatcher`, `HeaderContainsMatcher`, `HeaderRegexMatcher`, `StatusDiffMatcher`) so probes can express richer detection logic than the existing `StatusCodeMatcher`/`BodyContainsMatcher`/`CompositeMatcher` family.
- Each probe ships with a unit test that exercises the generator and at least one composite integration test through the full pipeline (mock HTTP target → matcher fires).
- Probes respect the existing `scan_profile` enum (`passive`, `standard`, `aggressive`) so destructive probes can be opted out without code changes.

### Non-goals

- HTTP request smuggling (CL.TE / TE.CL). The probe needs raw `net.Dial` because Go's `http.Client` rewrites conflicting framing headers. Deferred to a future PR that adds raw-socket DAST infrastructure.
- Browser-driven probes (DOM XSS, postMessage, CSP bypass). Those live in `cmd/dast-browser-worker/` and are out of scope here.
- Multi-step probes that require state across requests (full mass-assignment flow with create→read, deeper prototype pollution chain). The MASS and PROTO-POL probes here are simplified to single-request shape that catches the common case.
- Engine architecture changes. `TestCase` shape, `Endpoint` shape, scheduler, evidence capture, and worker dispatching are unchanged.

---

## 2. Background & current state

The DAST module under `internal/dast/` consists of:

- **`testcase.go`** — `TestCase` record (ID, RuleID, Name, Category, Severity, Confidence, Method, URL, Headers, Body, ContentType, Matcher) and the existing matcher types: `StatusCodeMatcher`, `BodyContainsMatcher`, `CompositeMatcher` (And/Or).
- **`generator.go`** — `Endpoint`, `Parameter`, `RequestBodySpec`, plus `GenerateTestCases(endpoints []Endpoint) []TestCase` which fans out per endpoint to six per-class generators (SQLi, XSS, PathTraversal, SSRF, IDOR, HeaderInjection).
- **`worker.go` / `natsworker.go`** — pull endpoints, run probes, capture evidence.

Existing DAST rule_ids referenced across the codebase:

| Rule_id | Source |
|---------|--------|
| `DAST-SQLI-001`, `DAST-XSS-001`, `DAST-PT-001`, `DAST-SSRF-001`, `DAST-IDOR-001`, `DAST-HI-001` | Hand-coded probes in `generator.go` |
| `SC-DAST-CSRF-001`, `SC-DAST-MIXED-001`, `SC-DAST-AUTOCOMPLETE-001`, `SC-DAST-INLINE-001`, `SC-DAST-AUTHZ-001`, `SC-DAST-XSS-001`, `SC-DAST-SSRF-001`, `SC-DAST-OPENREDIRECT-001`, `SC-DAST-SECHEADERS-001`, `SC-DAST-COOKIEFLAGS-001`, `SC-DAST-SQLI-001` | Passive/header-tier finding labels (CWE remediation packs in `internal/remediation/packs/` plus migration `021_dast_rule_ids`) |

Rule-ID convention this PR uses: **`DAST-<CLASS>-NNN`** to match the active-probe family. `SC-DAST-*` is reserved for passive findings and remediation-pack mapping; we are not extending that taxonomy here.

---

## 3. New probes (9)

| ID | Class | Active payload | Detection signal |
|----|-------|----------------|------------------|
| `DAST-XXE-001` | xxe | POST `<?xml ...><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>` | Response body contains `root:` followed by `:0:0:` (etc/passwd row) |
| `DAST-NOSQL-001` | nosql_injection | POST JSON body with `{"$ne": null}`, `{"$gt": ""}`, `{"$where": "1"}` substituted into authentication parameters | Response status 200 (login succeeded) where baseline credentials would 401 |
| `DAST-GRAPHQL-001` | graphql_introspection | POST `{"query":"{__schema{types{name}}}"}` to `/graphql`, `/api/graphql`, `/v1/graphql` | Response body contains `"__schema"` and `"types"` keys |
| `DAST-JWT-001` | jwt_alg_none | If endpoint advertises a JWT (Authorization header captured during baseline), re-sign with header `{"alg":"none","typ":"JWT"}` and empty signature | Probe response 200 instead of 401/403 |
| `DAST-JWT-002` | jwt_weak_secret | If captured token uses HS256, brute force against a 12-secret list (`secret`, `key`, `password`, `123456`, `admin`, `jwt`, `JWT`, `your-256-bit-secret`, `please-change-me`, `s3cr3t`, ``, `secretkey`) | Token verifies under one of the secrets → flag with the secret in evidence |
| `DAST-CRLF-001` | crlf_injection | Inject `%0d%0aSet-Cookie:%20pwn=1` into query parameter values | Response includes `Set-Cookie: pwn=1` header (echoed via response splitting) |
| `DAST-OPENREDIR-001` | open_redirect | Inject `https://example.org/sentinel-probe` and `//evil.example.org` into params named `redirect`, `next`, `url`, `return`, `goto`, `to` | Response status 30x with `Location` header containing the injected origin |
| `DAST-MASS-001` | mass_assignment | POST/PUT JSON body with extra fields the API didn't request (`is_admin: true`, `role: "admin"`, `verified: true`, `balance: 999999`) | Response 201/200 AND response body echoes one of the extra fields with the injected value |
| `DAST-PROTO-POL-001` | prototype_pollution | POST `{"__proto__":{"sentinelProbe":"polluted"}}` or `{"constructor":{"prototype":{"sentinelProbe":"polluted"}}}` | Response body, in this same request, contains `"sentinelProbe":"polluted"` (echoed via merged config), or response status switches from 400 baseline to 200 |

### 3.1 Profile gating

Probes are tagged with a minimum required `scan_profile`:

| Profile | Probes that run |
|---------|-----------------|
| `passive` | DAST-GRAPHQL-001 (read-only POST that returns schema), DAST-JWT-001 (re-sign uses the user's existing token; no new write), passive findings (header/cookie checks; not in this PR) |
| `standard` | All `passive` probes plus DAST-XXE-001, DAST-NOSQL-001, DAST-JWT-002, DAST-CRLF-001, DAST-OPENREDIR-001 |
| `aggressive` | All `standard` probes plus DAST-MASS-001, DAST-PROTO-POL-001 (these mutate state) |

The generator filters probes against the configured profile before emitting `TestCase`s. Implementation: each `generateXxxTests` returns `[]TestCase`, and the aggregator drops the entire bucket for probes whose minimum profile exceeds the scan's profile. The profile is plumbed through `GenerateTestCases(endpoints []Endpoint, profile string) []TestCase` — signature changes by adding `profile`. The legacy 6 probes default to `standard` minimum.

### 3.2 Auth-aware probes

`DAST-JWT-001` and `DAST-JWT-002` need a captured JWT to operate on. The existing scanner architecture has an `auth_config` (loaded by the worker before sending probes) that can already inject Authorization headers. We add a `CapturedJWT` field to the `Endpoint` model so the generator knows whether a JWT probe should fire. If `CapturedJWT == ""`, both JWT probes are skipped (logged at INFO level so the scan report shows the skip).

---

## 4. New matchers (4)

Add to `internal/dast/testcase.go` (or a new `matchers.go` if the file grows large):

```go
// BodyRegexMatcher fires when the regex matches the response body.
type BodyRegexMatcher struct {
    Pattern *regexp.Regexp
    Reason  string
}
func (m *BodyRegexMatcher) Match(_ *http.Response, body []byte) (bool, string) {
    if m.Pattern.Match(body) {
        return true, m.Reason
    }
    return false, ""
}

// HeaderContainsMatcher fires when a named header contains the substring.
type HeaderContainsMatcher struct {
    Name      string
    Substring string
    Reason    string
}
func (m *HeaderContainsMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
    for _, v := range resp.Header.Values(m.Name) {
        if strings.Contains(v, m.Substring) {
            return true, m.Reason
        }
    }
    return false, ""
}

// HeaderRegexMatcher fires when a named header matches the regex.
type HeaderRegexMatcher struct {
    Name    string
    Pattern *regexp.Regexp
    Reason  string
}
func (m *HeaderRegexMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
    for _, v := range resp.Header.Values(m.Name) {
        if m.Pattern.MatchString(v) {
            return true, m.Reason
        }
    }
    return false, ""
}

// StatusDiffMatcher fires when the response status differs from the
// baseline status the worker captured before probing the endpoint.
// `BaselineCode` is set by the worker after a baseline call; the matcher
// reads it from a context value.
type StatusDiffMatcher struct {
    BaselineCode int
    ProbeCode    int    // expected probe response code that signals success
    Reason       string
}
func (m *StatusDiffMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
    if resp.StatusCode == m.ProbeCode && resp.StatusCode != m.BaselineCode {
        return true, m.Reason
    }
    return false, ""
}
```

The existing `CompositeMatcher` uses these as children (e.g., `Composite{All: []ResponseMatcher{StatusCodeMatcher{200}, BodyRegexMatcher{...}}}`).

---

## 5. File structure

| Path | Change |
|------|--------|
| `internal/dast/generator.go` | Modify: add 9 probe-generator functions, extend `GenerateTestCases` signature with `profile` param, route by profile |
| `internal/dast/generator_test.go` | Modify: 9 new unit tests (one per probe), 1 test for profile gating |
| `internal/dast/matchers.go` | Create: `BodyRegexMatcher`, `HeaderContainsMatcher`, `HeaderRegexMatcher`, `StatusDiffMatcher` |
| `internal/dast/matchers_test.go` | Create: unit tests for the four matchers |
| `internal/dast/integration_test.go` | Modify: add 3 end-to-end probe tests against an `httptest.NewServer` (XXE, JWT alg=none, prototype pollution) |
| `internal/dast/testcase.go` | Modify: add `MinProfile string` field to `TestCase` so the worker can sanity-check; add `CapturedJWT string` to `Endpoint` |

---

## 6. Implementation strategy

Two PRs.

### PR D1 — Matchers + Endpoint extensions (~30 min)

- New `internal/dast/matchers.go` with the 4 matchers.
- New `internal/dast/matchers_test.go` covering each matcher's hit/miss behavior.
- Extend `Endpoint` (in `generator.go`) with optional `CapturedJWT string` field.
- Extend `TestCase` (in `testcase.go`) with optional `MinProfile string` field (zero value = `"standard"`).
- Extend `GenerateTestCases` signature to `GenerateTestCases(endpoints []Endpoint, profile string) []TestCase` — existing callers updated.
- All existing tests pass.

### PR D2 — Nine probe generators (~2.5 h)

- Add `generateXXETests`, `generateNoSQLITests`, `generateGraphQLITests`, `generateJWTAlgNoneTests`, `generateJWTWeakSecretTests`, `generateCRLFITests`, `generateOpenRedirectTests`, `generateMassAssignmentTests`, `generatePrototypePollutionTests` to `generator.go`.
- Update `GenerateTestCases` to call all nine and filter by `profile`.
- Each function: returns at minimum 1 `TestCase` per applicable parameter on each applicable endpoint, with a unit test asserting the count and the `RuleID`.
- Three end-to-end tests in `integration_test.go` covering XXE, JWT alg=none, prototype pollution against an `httptest` server.

Both PRs build a new `sentinelcore/dast-worker:dast-prN` image and deploy with `docker tag … :pilot` + `docker compose up -d dast-worker`. Rollback tag `dast-worker:pilot-pre-dast-expansion` taken before PR D1.

---

## 7. Testing

### 7.1 Unit tests

Each new probe generator gets a test that asserts:
- Given a mock endpoint with one query parameter, the function emits ≥ 1 `TestCase`.
- Each emitted `TestCase` has the expected `RuleID`, `Category`, `Severity`, `Confidence`.
- For probes that touch multiple parameter types (XXE/NoSQL on JSON bodies; CRLF on query/path), every applicable shape is covered.

Each new matcher gets a hit-and-miss table-driven test.

### 7.2 Integration tests

Three end-to-end smoke tests against `httptest.NewServer` handlers that simulate vulnerable behavior:

- **XXE:** handler that echoes the parsed XML's first text node — payload sets `&a;` to file content; matcher should fire on `root:`-shaped echo.
- **JWT alg=none:** handler that decodes the JWT and trusts `alg=none`; probe re-signs and expects 200.
- **Prototype pollution:** handler that JSON-merges the request body into a config object and echoes the config; probe expects `"sentinelProbe":"polluted"` in the echo.

Negative tests: against a handler that DOES NOT exhibit the vulnerability, the matcher must not fire.

### 7.3 Profile gating test

One test asserts that:
- `profile="passive"` emits only GraphQL + JWT-001 probes
- `profile="standard"` emits all except MASS + PROTO-POL
- `profile="aggressive"` emits all 9 + the legacy 6 = 15 buckets

---

## 8. Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Active probes (MASS, PROTO-POL) mutate target state | Medium — could create real records on a customer's prod system | Gated behind `aggressive` profile only. Document in scan-profile docs that aggressive runs include state-mutating probes. |
| JWT probes silently skip when no token is captured | Low — coverage gap, not a false reading | Worker logs an INFO line per skipped JWT probe; scan report includes a "skipped probes" tally so operators can see why. |
| GraphQL introspection probes hit non-existent `/graphql` paths and 404, wasting requests | Low — performance, not correctness | Probe sends to a fixed list `[/graphql, /api/graphql, /v1/graphql]` only; bails after 404. No expensive enumeration. |
| Open-redirect probe payloads with `//evil.example.org` may trigger SSRF defenses on the target | Low — false negatives if defense intercepts | Use multiple shapes (`https://example.org/sentinel-probe`, `//example.org`); the matcher fires on any matching `Location` echo. |
| Prototype pollution probe is a single request — won't catch chained pollution → privilege escalation | Medium — false negatives | Documented limitation. Multi-step pollution detection is a future PR. |

---

## 9. Open questions

(None — addressed during brainstorming.)
