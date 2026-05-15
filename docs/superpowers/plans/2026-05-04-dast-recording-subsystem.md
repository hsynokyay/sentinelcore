# DAST Recording Subsystem — Implementation Plan (Plan #3 of 6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Ship a CLI tool (`sentinelcore-cli dast record`) that opens a sandboxed Chrome session via chromedp, lets the customer log in to their target application (solving CAPTCHA / MFA themselves), captures the resulting session jar, and uploads it as an approved-pending bundle via the existing `/api/v1/dast/bundles` endpoint. Add `RecordedLoginStrategy` to the authbroker that loads recording-typed bundles for one-shot session reuse.

**Architecture:** 4 PRs. PR A extends the bundle CRUD to accept `type=recorded_login` and adds a `recording_metadata` JSON field (Chrome version, action count placeholder, captcha-in-flow flag, recorded-at timestamp). PR B adds the `internal/authbroker/recording/` package — a chromedp-based recorder that opens a sandboxed browser, watches cookie events, and produces a `RecordedSession` artifact. PR C adds the CLI command `sentinelcore-cli dast record --target <url> --project <id>`. PR D adds `RecordedLoginStrategy` (one-shot mode only — automatable refresh deferred to Plan #4 / replay engine).

**Tech Stack:** Go 1.23, chromedp (already in go.mod), existing `/api/v1/dast/bundles` POST endpoint, no new external deps.

**Spec reference:** `docs/superpowers/specs/2026-05-04-dast-auth-captcha-design.md` — sections 5 (recording subsystem), 6.1 (one-shot mode), 8.2 (RecordedLoginStrategy).

**Plan #3 of 6.** Plans #1 and #2 merged. Plan #4 (replay engine + automatable refresh) builds on this. Plan #5 SDKs + SIEM, Plan #6 pen-test follow.

**Scope cuts vs spec §5:**
- **No action list capture in this plan.** The chromedp instrumentation captures cookies and final URL only; the action list (navigate / fill / click / wait events per spec §5.2) is deferred to Plan #4 because it's only useful when paired with a replay engine. One-shot bundles produced by Plan #3 carry an empty action list.
- **No Vault-backed credential field detection.** Spec §5.3 requires literal credentials never to be stored. Plan #3 satisfies this trivially because we DO NOT capture form-fill values at all — the user types them in the browser and we only capture the resulting session jar.
- **No browser fingerprint canonicalization.** Recorded `user_agent` string is stored verbatim; canonical fingerprint comparison is a Plan #4 concern when refresh tries to re-issue.
- **No Web UI.** CLI only in this plan; UI is a separate plan.

---

## Working environment

- **Branch:** `feat/dast-recording-2026-05` cut from `phase2/api-dast` HEAD (which has Plans #1 + #2 merged).
- **Worktree:** `/Users/okyay/Documents/SentinelCore/.worktrees/dast-recording`.
- **Migrations** start at **046** (Plan #2 used 045).
- **Build/deploy** for the controlplane only (CLI is a binary, not a service).

---

## Existing infrastructure (verified)

- `internal/browser/chrome.go` — chromedp launcher with sandbox flags.
- `internal/browser/auth.go` — `InjectCookies` already harden cookies. We READ cookies via chromedp; do not need a new injection path.
- `cmd/cli/main.go` — switch-style command dispatch. We add a `dast` subcommand alongside `bootstrap`, `update`, `version`.
- `internal/dast/bundles/bundle.go` — `Bundle` struct includes `Type` ('session_import' or 'recorded_login'), `CapturedSession`, metadata-jsonb. Type 'recorded_login' is already in the schema CHECK constraint.
- `internal/controlplane/dast_bundles_handler.go` — `Create` currently rejects `type != "session_import"`. Plan #3 PR A relaxes this.

---

## File structure

### New files

| Path | Responsibility |
|------|----------------|
| `migrations/046_dast_bundle_recording_metadata.up.sql` | Add `recording_metadata JSONB` column to `dast_auth_bundles` |
| `migrations/046_dast_bundle_recording_metadata.down.sql` | Rollback |
| `internal/authbroker/recording/recorder.go` | chromedp-based recorder + `RecordedSession` type |
| `internal/authbroker/recording/recorder_test.go` | Recorder unit tests with stub chromedp |
| `cmd/cli/dast.go` | `dast record` subcommand entry point |
| `cmd/cli/dast_record.go` | Recording flow: launch browser, capture, upload |
| `internal/authbroker/recorded_login_strategy.go` | `RecordedLoginStrategy` (one-shot mode) |
| `internal/authbroker/recorded_login_strategy_test.go` | Strategy tests |

### Modified files

| Path | Reason |
|------|--------|
| `cmd/cli/main.go` | Add `dast` case to top-level switch |
| `internal/dast/bundles/bundle.go` | Add `RecordingMetadata` field |
| `internal/dast/bundles/store.go` | Persist `recording_metadata` on Save / read on Load |
| `internal/controlplane/dast_bundles_handler.go` | Accept `type=recorded_login`; persist `recording_metadata` |
| `internal/authbroker/strategy.go` | (No change needed — strategy registers itself like SessionImport) |

---

## PR 0 — Pre-flight

- [ ] **Step 1: Verify branch + create worktree**

```
cd /Users/okyay/Documents/SentinelCore
git fetch origin
git worktree add /Users/okyay/Documents/SentinelCore/.worktrees/dast-recording \
  -b feat/dast-recording-2026-05 origin/phase2/api-dast
cd .worktrees/dast-recording
git branch --show-current
```

Expected: prints `feat/dast-recording-2026-05`.

- [ ] **Step 2: Tag rollback image**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/controlplane:pilot sentinelcore/controlplane:pilot-pre-recording"
```

- [ ] **Step 3: Sanity test**

```
go test ./internal/dast/... ./internal/authbroker/... ./internal/controlplane/...
```

Expected: PASS.

---

## PR A — Schema + bundle metadata extension (3 tasks)

### Task A.1: Migration 046

**Files:**
- Create: `migrations/046_dast_bundle_recording_metadata.up.sql`
- Create: `migrations/046_dast_bundle_recording_metadata.down.sql`

- [ ] **Step 1: Write migration**

`up.sql`:
```sql
-- Recording-specific metadata (browser fingerprint, recorded-at, captcha
-- in flow, action count). Stored as JSONB to allow forward-compatible
-- field additions without schema changes. NULL for session_import bundles.
ALTER TABLE dast_auth_bundles
    ADD COLUMN recording_metadata JSONB;

CREATE INDEX dast_auth_bundles_recording
    ON dast_auth_bundles((recording_metadata->>'browser_user_agent'))
    WHERE type = 'recorded_login';
```

`down.sql`:
```sql
DROP INDEX IF EXISTS dast_auth_bundles_recording;
ALTER TABLE dast_auth_bundles DROP COLUMN IF EXISTS recording_metadata;
```

- [ ] **Step 2: Commit**

```
git add migrations/046_dast_bundle_recording_metadata.up.sql migrations/046_dast_bundle_recording_metadata.down.sql
git commit -m "feat(db): add recording_metadata JSONB column to dast_auth_bundles"
```

### Task A.2: Extend Bundle struct + store

**Files:**
- Modify: `internal/dast/bundles/bundle.go`
- Modify: `internal/dast/bundles/store.go`

- [ ] **Step 1: Add `RecordingMetadata` field**

Add to `Bundle` struct in `bundle.go`:

```go
// RecordingMetadata is non-credential metadata about a recorded_login bundle.
// NULL for session_import. Stored as JSONB in the DB; serialized as a sub-
// object in the canonical JSON form used for HMAC.
type RecordingMetadata struct {
    BrowserUserAgent  string    `json:"browser_user_agent,omitempty"`
    BrowserVersion    string    `json:"browser_version,omitempty"`
    RecordedAt        time.Time `json:"recorded_at,omitempty"`
    RecordingDuration int64     `json:"recording_duration_ms,omitempty"`
    CaptchaDetected   bool      `json:"captcha_detected,omitempty"`
    FinalURL          string    `json:"final_url,omitempty"`
    ActionCount       int       `json:"action_count,omitempty"` // 0 in v1
}
```

Add to `Bundle`:
```go
RecordingMetadata *RecordingMetadata `json:"recording_metadata,omitempty"`
```

Update `CanonicalJSON()` to include `RecordingMetadata` when non-nil. The `recording_metadata` field appears AFTER `captured_session` in the canonical form.

- [ ] **Step 2: Update PostgresStore Save and Load**

In `store.go` `Save()`:
- Add new column to INSERT: `recording_metadata`
- If `b.RecordingMetadata != nil`, marshal to JSON and pass; else pass NULL

In `Load()`:
- Add column to SELECT: `recording_metadata`
- Scan into a `*[]byte` (nullable); if non-empty, unmarshal into `*RecordingMetadata` and set on the returned bundle

In `ListPending()`:
- No change needed (`BundleSummary` doesn't include the recording metadata; lookup-on-demand)

- [ ] **Step 3: Build + test**

```
go build ./internal/dast/bundles/
go test ./internal/dast/bundles/
```

Expected: PASS.

- [ ] **Step 4: Commit**

```
git add internal/dast/bundles/bundle.go internal/dast/bundles/store.go
git commit -m "feat(dast/bundles): add RecordingMetadata to Bundle struct + persistence"
```

### Task A.3: Relax handler to accept `recorded_login`

**Files:**
- Modify: `internal/controlplane/dast_bundles_handler.go`

- [ ] **Step 1: Update Create handler**

Find the existing validation:
```go
if req.ProjectID == "" || req.TargetHost == "" || req.Type != "session_import" {
```

Replace the type check:
```go
if req.ProjectID == "" || req.TargetHost == "" {
    http.Error(w, "invalid request: project_id, target_host required", http.StatusBadRequest)
    return
}
if req.Type != "session_import" && req.Type != "recorded_login" {
    http.Error(w, "invalid type: must be session_import or recorded_login", http.StatusBadRequest)
    return
}
```

Add `RecordingMetadata *bundles.RecordingMetadata` field to `CreateBundleRequest` struct. When present, copy it onto the `bundles.Bundle` instance before calling `store.Save`.

- [ ] **Step 2: Build**

```
go build ./internal/controlplane/
```

- [ ] **Step 3: Commit**

```
git add internal/controlplane/dast_bundles_handler.go
git commit -m "feat(controlplane): accept type=recorded_login + recording_metadata in bundle create"
```

PR A complete.

---

## PR B — chromedp recorder library (4 tasks)

### Task B.1: `RecordedSession` type + recorder skeleton

**Files:**
- Create: `internal/authbroker/recording/recorder.go`

- [ ] **Step 1: Implement recorder**

```go
// Package recording provides a chromedp-based browser recorder for DAST
// authenticated scans. Customers run it locally or in a guided flow to
// capture a logged-in session jar (cookies + final URL + UA fingerprint)
// for an application protected by CAPTCHA or MFA. The recorder does NOT
// store form-fill values — credentials remain in the user's head; only
// the resulting session is captured.
package recording

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/chromedp/cdproto/network"
    "github.com/chromedp/chromedp"
)

// RecordedSession captures the state of a logged-in browser session at the
// moment recording stopped.
type RecordedSession struct {
    Cookies          []*http.Cookie    // session jar at stop time
    Headers          map[string]string // last response headers (selected)
    FinalURL         string            // URL at stop time
    BrowserUserAgent string            // navigator.userAgent
    StartedAt        time.Time
    StoppedAt        time.Time
    CaptchaDetected  bool
}

// Options control recording behavior.
type Options struct {
    TargetURL        string
    AllowedHosts     []string      // network filter; only these hosts are reachable
    HeadlessFallback bool          // if true, run headless (CI/test mode); default false
    StopWhenURL      string        // optional: stop when navigation reaches this URL
    Timeout          time.Duration // hard cap on recording duration
}

// Recorder owns the chromedp browser context and event subscriptions.
type Recorder struct {
    opts            Options
    cookies         []*network.Cookie
    capturedHeaders map[string]string
    finalURL        string
    captchaDetected bool
    userAgent       string
    startedAt       time.Time
}

// New returns a Recorder ready to Run.
func New(opts Options) *Recorder {
    if opts.Timeout == 0 {
        opts.Timeout = 10 * time.Minute
    }
    return &Recorder{
        opts:            opts,
        capturedHeaders: make(map[string]string),
    }
}

// Run launches Chrome, navigates to TargetURL, and blocks until the user
// signals stop (returns nil) OR the timeout/StopWhenURL fires (returns
// the captured session). Pass a context that the caller can cancel.
func (r *Recorder) Run(ctx context.Context) (*RecordedSession, error) {
    allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
        chromedp.Flag("headless", r.opts.HeadlessFallback),
        chromedp.Flag("disable-extensions", true),
        chromedp.Flag("disable-features", "Autofill,FillingAcrossAffiliations,ChromeCleanup,NetworkService,SafeBrowsingEnhancedProtection"),
        chromedp.NoFirstRun,
        chromedp.NoDefaultBrowserCheck,
    )
    allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
    defer allocCancel()

    bctx, bcancel := chromedp.NewContext(allocCtx)
    defer bcancel()

    timeoutCtx, timeoutCancel := context.WithTimeout(bctx, r.opts.Timeout)
    defer timeoutCancel()

    r.startedAt = time.Now()

    // Subscribe to navigation + response events.
    chromedp.ListenTarget(timeoutCtx, func(ev interface{}) {
        switch e := ev.(type) {
        case *network.EventResponseReceived:
            r.captureHeaders(e.Response)
            if r.opts.StopWhenURL != "" && e.Response.URL == r.opts.StopWhenURL {
                bcancel()
            }
        }
    })

    // Initial navigate.
    if err := chromedp.Run(timeoutCtx,
        network.Enable(),
        chromedp.Navigate(r.opts.TargetURL),
    ); err != nil {
        return nil, fmt.Errorf("recording: initial navigate: %w", err)
    }

    // Block until ctx canceled (user pressed Ctrl+C) or timeout / stop URL hit.
    <-timeoutCtx.Done()

    // Capture final state.
    var ua, finalURL string
    cookies, err := r.fetchCookies(allocCtx)
    if err != nil {
        return nil, fmt.Errorf("recording: fetch cookies: %w", err)
    }
    _ = chromedp.Run(allocCtx,
        chromedp.Evaluate(`navigator.userAgent`, &ua),
        chromedp.Evaluate(`window.location.href`, &finalURL),
    )

    httpCookies := make([]*http.Cookie, 0, len(cookies))
    for _, c := range cookies {
        if !hostAllowed(c.Domain, r.opts.AllowedHosts) {
            continue
        }
        httpCookies = append(httpCookies, &http.Cookie{
            Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
            HttpOnly: c.HTTPOnly, Secure: c.Secure,
        })
    }

    return &RecordedSession{
        Cookies:          httpCookies,
        Headers:          r.capturedHeaders,
        FinalURL:         finalURL,
        BrowserUserAgent: ua,
        StartedAt:        r.startedAt,
        StoppedAt:        time.Now(),
        CaptchaDetected:  r.captchaDetected,
    }, nil
}

func (r *Recorder) fetchCookies(ctx context.Context) ([]*network.Cookie, error) {
    var cookies []*network.Cookie
    err := chromedp.Run(ctx,
        chromedp.ActionFunc(func(ctx context.Context) error {
            c, err := network.GetAllCookies().Do(ctx)
            cookies = c
            return err
        }),
    )
    return cookies, err
}

func (r *Recorder) captureHeaders(resp *network.Response) {
    if resp == nil { return }
    // Capture only Authorization-class response headers — never request
    // headers (which would include user-typed credentials in basic auth).
    for k, v := range resp.Headers {
        switch k {
        case "Authorization", "Set-Cookie":
            // already covered by cookie jar; skip Set-Cookie capture
        case "Authentication-Info":
            r.capturedHeaders[k] = fmt.Sprint(v)
        }
    }
    // Heuristic CAPTCHA detection: response URL contains known captcha
    // hostnames.
    url := resp.URL
    for _, marker := range []string{"google.com/recaptcha", "hcaptcha.com", "challenges.cloudflare.com"} {
        if contains(url, marker) {
            r.captchaDetected = true
        }
    }
}

func hostAllowed(domain string, allowed []string) bool {
    if len(allowed) == 0 { return true }
    for _, h := range allowed {
        if domain == h || domain == "."+h {
            return true
        }
    }
    return false
}

func contains(s, sub string) bool {
    return len(s) >= len(sub) && (s == sub || (len(s) > len(sub) && (indexOf(s, sub) >= 0)))
}

func indexOf(s, sub string) int {
    for i := 0; i+len(sub) <= len(s); i++ {
        if s[i:i+len(sub)] == sub { return i }
    }
    return -1
}
```

NOTE: The `contains` / `indexOf` helpers can be replaced with `strings.Contains` from the stdlib — written inline above to make the file self-contained for the example. Replace with `import "strings"` and `strings.Contains(s, sub)` in the actual code.

- [ ] **Step 2: Build**

```
go build ./internal/authbroker/recording/
```

Expected: success.

- [ ] **Step 3: Commit**

```
git add internal/authbroker/recording/recorder.go
git commit -m "feat(recording): add chromedp-based session recorder"
```

### Task B.2: Recorder unit tests

**Files:**
- Create: `internal/authbroker/recording/recorder_test.go`

Real chromedp tests require a Chrome binary; skip them in CI by default. Implement structural tests that don't need a browser.

- [ ] **Step 1: Write tests**

```go
package recording

import (
    "testing"
    "time"
)

func TestNew_DefaultsTimeout(t *testing.T) {
    r := New(Options{TargetURL: "https://app.bank.tld/login"})
    if r.opts.Timeout != 10*time.Minute {
        t.Errorf("expected 10min default, got %v", r.opts.Timeout)
    }
}

func TestHostAllowed_Empty(t *testing.T) {
    if !hostAllowed("any.example.com", nil) {
        t.Error("expected nil allowed list to permit any host")
    }
}

func TestHostAllowed_Match(t *testing.T) {
    if !hostAllowed("app.bank.tld", []string{"app.bank.tld"}) {
        t.Error("expected exact match to pass")
    }
    if !hostAllowed(".app.bank.tld", []string{"app.bank.tld"}) {
        t.Error("expected dot-prefixed domain match")
    }
    if hostAllowed("evil.bank.tld", []string{"app.bank.tld"}) {
        t.Error("expected non-matching host to be rejected")
    }
}

func TestRecorder_LiveBrowserSkipped(t *testing.T) {
    t.Skip("requires Chrome binary; covered by integration tests when CHROME_BINARY set")
}
```

- [ ] **Step 2: Run**

```
go test ./internal/authbroker/recording/ -v
```

Expected: 4 tests; 1 SKIP, 3 PASS.

- [ ] **Step 3: Commit**

```
git add internal/authbroker/recording/recorder_test.go
git commit -m "test(recording): add recorder unit tests (host filter + defaults)"
```

### Task B.3: Replace inline string helpers with stdlib

Apply the cleanup mentioned in the recorder.go comment:

- [ ] **Step 1: Replace `contains` and `indexOf` with `strings.Contains`**

Edit `internal/authbroker/recording/recorder.go`:
- Add `"strings"` to imports
- Replace the body of `contains(s, sub string)` to `return strings.Contains(s, sub)` (or just delete `contains` and call `strings.Contains` inline)
- Delete the `indexOf` function

- [ ] **Step 2: Build + test**

```
go build ./internal/authbroker/recording/
go test ./internal/authbroker/recording/
```

- [ ] **Step 3: Commit**

```
git add internal/authbroker/recording/recorder.go
git commit -m "chore(recording): use strings.Contains instead of inline helper"
```

### Task B.4: PR B push

```
git push -u origin feat/dast-recording-2026-05
```

PR B complete.

---

## PR C — CLI `dast record` command (3 tasks)

### Task C.1: Add `dast` subcommand to CLI

**Files:**
- Modify: `cmd/cli/main.go`
- Create: `cmd/cli/dast.go`

- [ ] **Step 1: Edit main.go switch**

Add a `case "dast":` between existing cases:

```go
case "dast":
    if err := runDastCommand(os.Args[2:]); err != nil {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
        os.Exit(1)
    }
```

Add the new line to `printUsage()`:
```
fmt.Println("  dast       DAST commands (record, ...)")
```

- [ ] **Step 2: Implement `runDastCommand`**

Create `cmd/cli/dast.go`:

```go
package main

import (
    "fmt"
    "os"
)

// runDastCommand routes "dast <subcommand>" to the right handler.
func runDastCommand(args []string) error {
    if len(args) == 0 {
        printDastUsage()
        return fmt.Errorf("dast: missing subcommand")
    }
    switch args[0] {
    case "record":
        return runDastRecord(args[1:])
    default:
        printDastUsage()
        return fmt.Errorf("dast: unknown subcommand %q", args[0])
    }
}

func printDastUsage() {
    fmt.Fprintln(os.Stderr, "Usage: sentinelcore-cli dast <subcommand> [options]")
    fmt.Fprintln(os.Stderr)
    fmt.Fprintln(os.Stderr, "Subcommands:")
    fmt.Fprintln(os.Stderr, "  record    Record an authenticated session for DAST scanning")
}
```

- [ ] **Step 3: Build**

```
go build ./cmd/cli/
```

- [ ] **Step 4: Commit**

```
git add cmd/cli/main.go cmd/cli/dast.go
git commit -m "feat(cli): add 'dast' subcommand dispatcher"
```

### Task C.2: Implement `dast record`

**Files:**
- Create: `cmd/cli/dast_record.go`

- [ ] **Step 1: Implement**

```go
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/sentinelcore/sentinelcore/internal/authbroker/recording"
)

func runDastRecord(args []string) error {
    fs := flag.NewFlagSet("dast record", flag.ContinueOnError)
    target := fs.String("target", "", "URL of the application's login page (required)")
    project := fs.String("project", "", "Project UUID under SentinelCore (required)")
    apiBase := fs.String("api", "https://sentinelcore.resiliencetech.com.tr", "Controlplane base URL")
    apiToken := fs.String("token", "", "API access token (or env SENTINELCORE_TOKEN)")
    headless := fs.Bool("headless", false, "Run Chrome headless (no UI; for CI testing)")
    stopAt := fs.String("stop-at", "", "Optional URL prefix; recording stops when navigation reaches it")
    timeoutMin := fs.Int("timeout", 10, "Hard timeout in minutes")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *target == "" || *project == "" {
        fs.Usage()
        return fmt.Errorf("--target and --project are required")
    }
    token := *apiToken
    if token == "" {
        token = os.Getenv("SENTINELCORE_TOKEN")
    }
    if token == "" {
        return fmt.Errorf("--token (or env SENTINELCORE_TOKEN) required")
    }

    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    fmt.Println("==================================================================")
    fmt.Printf("Starting recording session for %s\n", *target)
    fmt.Printf("Press Ctrl+C in this terminal when you finish logging in.\n")
    if *stopAt != "" {
        fmt.Printf("OR navigate to: %s (recording stops automatically)\n", *stopAt)
    }
    fmt.Println("==================================================================")

    rec := recording.New(recording.Options{
        TargetURL:        *target,
        HeadlessFallback: *headless,
        StopWhenURL:      *stopAt,
        Timeout:          time.Duration(*timeoutMin) * time.Minute,
    })

    session, err := rec.Run(ctx)
    if err != nil {
        return fmt.Errorf("recording failed: %w", err)
    }

    if len(session.Cookies) == 0 {
        return fmt.Errorf("recording captured no cookies — login may not have completed")
    }

    fmt.Printf("\nCaptured %d cookies, %d response headers.\n", len(session.Cookies), len(session.Headers))
    fmt.Printf("Final URL: %s\n", session.FinalURL)
    if session.CaptchaDetected {
        fmt.Println("CAPTCHA detected in flow — bundle will be marked one-shot only.")
    }

    bundleID, err := uploadBundle(ctx, *apiBase, token, *project, session)
    if err != nil {
        return fmt.Errorf("upload bundle: %w", err)
    }
    fmt.Printf("Uploaded as bundle: %s (status: pending_review)\n", bundleID)
    fmt.Println("Have your reviewer approve via /api/v1/dast/bundles/<id>/approve.")
    return nil
}

func uploadBundle(ctx context.Context, apiBase, token, projectID string, session *recording.RecordedSession) (string, error) {
    type cookie struct {
        Name     string `json:"name"`
        Value    string `json:"value"`
        Domain   string `json:"domain,omitempty"`
        Path     string `json:"path,omitempty"`
        HttpOnly bool   `json:"http_only,omitempty"`
        Secure   bool   `json:"secure,omitempty"`
    }
    type sessionCapture struct {
        Cookies []cookie          `json:"cookies"`
        Headers map[string]string `json:"headers"`
    }
    type recordingMeta struct {
        BrowserUserAgent  string `json:"browser_user_agent"`
        RecordedAt        string `json:"recorded_at"`
        RecordingDuration int64  `json:"recording_duration_ms"`
        CaptchaDetected   bool   `json:"captcha_detected"`
        FinalURL          string `json:"final_url"`
    }
    type req struct {
        ProjectID         string         `json:"project_id"`
        TargetHost        string         `json:"target_host"`
        Type              string         `json:"type"`
        CapturedSession   sessionCapture `json:"captured_session"`
        TTLSeconds        int            `json:"ttl_seconds"`
        ACL               []map[string]any `json:"acl"`
        RecordingMetadata recordingMeta  `json:"recording_metadata"`
    }

    cookies := make([]cookie, 0, len(session.Cookies))
    for _, c := range session.Cookies {
        cookies = append(cookies, cookie{
            Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
            HttpOnly: c.HttpOnly, Secure: c.Secure,
        })
    }

    targetHost := hostFromURL(session.FinalURL)

    body, _ := json.Marshal(req{
        ProjectID: projectID, TargetHost: targetHost, Type: "recorded_login",
        CapturedSession: sessionCapture{Cookies: cookies, Headers: session.Headers},
        TTLSeconds: 86400,
        ACL: []map[string]any{{"project_id": projectID}},
        RecordingMetadata: recordingMeta{
            BrowserUserAgent: session.BrowserUserAgent,
            RecordedAt:       session.StoppedAt.Format(time.RFC3339Nano),
            RecordingDuration: session.StoppedAt.Sub(session.StartedAt).Milliseconds(),
            CaptchaDetected:  session.CaptchaDetected,
            FinalURL:         session.FinalURL,
        },
    })

    httpReq, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/api/v1/dast/bundles", bytes.NewReader(body))
    if err != nil { return "", err }
    httpReq.Header.Set("Authorization", "Bearer "+token)
    httpReq.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(httpReq)
    if err != nil { return "", err }
    defer resp.Body.Close()
    out, _ := io.ReadAll(resp.Body)
    if resp.StatusCode != http.StatusCreated {
        return "", fmt.Errorf("api error %d: %s", resp.StatusCode, string(out))
    }
    var parsed struct {
        BundleID string `json:"bundle_id"`
        Status   string `json:"status"`
    }
    if err := json.Unmarshal(out, &parsed); err != nil { return "", err }
    return parsed.BundleID, nil
}

func hostFromURL(u string) string {
    // Trivial host extractor; returns "" if URL invalid
    if u == "" { return "" }
    // Strip scheme
    for _, prefix := range []string{"https://", "http://"} {
        if len(u) >= len(prefix) && u[:len(prefix)] == prefix {
            u = u[len(prefix):]
            break
        }
    }
    for i := 0; i < len(u); i++ {
        if u[i] == '/' || u[i] == '?' || u[i] == '#' {
            return u[:i]
        }
    }
    return u
}
```

NOTE: For production, replace `hostFromURL` with `net/url` parser. The inline implementation is for plan brevity.

- [ ] **Step 2: Replace `hostFromURL` with stdlib**

```go
import "net/url"

func hostFromURL(u string) string {
    parsed, err := url.Parse(u)
    if err != nil || parsed == nil {
        return ""
    }
    return parsed.Host
}
```

- [ ] **Step 3: Build**

```
go build ./cmd/cli/
```

- [ ] **Step 4: Test the CLI parses**

```
./cli dast record --help 2>&1 | head -10
# OR if not built:
go run ./cmd/cli dast record --help 2>&1 | head -10
```

Expected: usage text printed.

- [ ] **Step 5: Commit**

```
git add cmd/cli/dast_record.go
git commit -m "feat(cli): add 'dast record' command for chromedp session capture"
```

### Task C.3: PR C push

```
git push
```

PR C complete; CLI ships in next deploy.

---

## PR D — RecordedLoginStrategy + tests + deploy (4 tasks)

### Task D.1: RecordedLoginStrategy

**Files:**
- Create: `internal/authbroker/recorded_login_strategy.go`

- [ ] **Step 1: Implement strategy**

```go
package authbroker

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

// RecordedLoginStrategy authenticates by loading a bundle of type
// 'recorded_login'. In v1 (one-shot mode), it returns the captured session
// directly. Plan #4 adds automatable refresh that replays the recorded
// action list to obtain a fresh session.
type RecordedLoginStrategy struct {
    Bundles bundles.BundleStore
}

func (s *RecordedLoginStrategy) Name() string { return "recorded_login" }

func (s *RecordedLoginStrategy) Authenticate(ctx context.Context, cfg AuthConfig) (*Session, error) {
    if cfg.BundleID == "" {
        return nil, fmt.Errorf("recorded_login: bundle_id required")
    }
    if cfg.CustomerID == "" {
        return nil, fmt.Errorf("recorded_login: customer_id required")
    }
    if cfg.ProjectID == "" {
        return nil, fmt.Errorf("recorded_login: project_id required")
    }
    if s.Bundles == nil {
        return nil, fmt.Errorf("recorded_login: bundle store not configured")
    }

    b, err := s.Bundles.Load(ctx, cfg.BundleID, cfg.CustomerID)
    if err != nil {
        return nil, fmt.Errorf("recorded_login: load: %w", err)
    }
    if b.Type != "recorded_login" {
        return nil, fmt.Errorf("recorded_login: wrong bundle type %q", b.Type)
    }
    if b.ExpiresAt.Before(time.Now()) {
        return nil, fmt.Errorf("recorded_login: bundle expired")
    }

    var scopeID *string
    if cfg.ScopeID != "" {
        v := cfg.ScopeID
        scopeID = &v
    }
    ok, err := s.Bundles.CheckACL(ctx, b.ID, cfg.ProjectID, scopeID)
    if err != nil {
        return nil, fmt.Errorf("recorded_login: acl: %w", err)
    }
    if !ok {
        return nil, fmt.Errorf("recorded_login: bundle not authorized for project")
    }

    httpCookies := make([]*http.Cookie, 0, len(b.CapturedSession.Cookies))
    for _, c := range b.CapturedSession.Cookies {
        httpCookies = append(httpCookies, &http.Cookie{
            Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
            HttpOnly: c.HttpOnly, Secure: c.Secure,
        })
    }
    headers := make(map[string]string, len(b.CapturedSession.Headers))
    for k, v := range b.CapturedSession.Headers {
        headers[k] = v
    }

    _ = s.Bundles.IncUseCount(ctx, b.ID)

    return &Session{
        Cookies:   httpCookies,
        Headers:   headers,
        ExpiresAt: b.ExpiresAt,
    }, nil
}

// Refresh in v1 returns ErrManualRefreshRequired. Plan #4 implements
// automatable refresh via the replay engine.
func (s *RecordedLoginStrategy) Refresh(_ context.Context, _ *Session, _ AuthConfig) (*Session, error) {
    return nil, fmt.Errorf("recorded_login: automatable refresh requires Plan #4 replay engine; use one-shot mode")
}

func (s *RecordedLoginStrategy) Validate(_ context.Context, session *Session) (bool, error) {
    return !session.IsExpired() && (len(session.Cookies) > 0 || len(session.Headers) > 0), nil
}
```

- [ ] **Step 2: Build**

```
go build ./internal/authbroker/
```

- [ ] **Step 3: Commit**

```
git add internal/authbroker/recorded_login_strategy.go
git commit -m "feat(authbroker): add RecordedLoginStrategy (one-shot mode)"
```

### Task D.2: Strategy tests

**Files:**
- Create: `internal/authbroker/recorded_login_strategy_test.go`

- [ ] **Step 1: Write tests**

```go
package authbroker

import (
    "context"
    "errors"
    "testing"
    "time"

    "github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

type recordedFakeStore struct {
    bundle *bundles.Bundle
    err    error
}

func (s *recordedFakeStore) Save(_ context.Context, _ *bundles.Bundle, _ string) (string, error) { return "", nil }
func (s *recordedFakeStore) Load(_ context.Context, _, _ string) (*bundles.Bundle, error) {
    return s.bundle, s.err
}
func (s *recordedFakeStore) UpdateStatus(_ context.Context, _, _ string) error { return nil }
func (s *recordedFakeStore) Revoke(_ context.Context, _, _ string) error { return nil }
func (s *recordedFakeStore) SoftDelete(_ context.Context, _ string) error { return nil }
func (s *recordedFakeStore) IncUseCount(_ context.Context, _ string) error { return nil }
func (s *recordedFakeStore) AddACL(_ context.Context, _, _ string, _ *string) error { return nil }
func (s *recordedFakeStore) CheckACL(_ context.Context, _, _ string, _ *string) (bool, error) { return true, nil }
func (s *recordedFakeStore) Approve(_ context.Context, _, _ string, _ int) error { return nil }
func (s *recordedFakeStore) Reject(_ context.Context, _, _, _ string) error { return nil }
func (s *recordedFakeStore) ListPending(_ context.Context, _ string, _, _ int) ([]*bundles.BundleSummary, error) { return nil, nil }

func TestRecordedLogin_HappyPath(t *testing.T) {
    store := &recordedFakeStore{
        bundle: &bundles.Bundle{
            ID: "b1", Type: "recorded_login",
            ExpiresAt: time.Now().Add(24 * time.Hour),
            CapturedSession: bundles.SessionCapture{
                Cookies: []bundles.Cookie{{Name: "sid", Value: "v"}},
                Headers: map[string]string{},
            },
        },
    }
    s := &RecordedLoginStrategy{Bundles: store}
    sess, err := s.Authenticate(context.Background(), AuthConfig{
        BundleID: "b1", CustomerID: "c1", ProjectID: "p1",
    })
    if err != nil {
        t.Fatalf("Authenticate: %v", err)
    }
    if len(sess.Cookies) != 1 || sess.Cookies[0].Name != "sid" {
        t.Errorf("unexpected cookies: %+v", sess.Cookies)
    }
}

func TestRecordedLogin_WrongType(t *testing.T) {
    store := &recordedFakeStore{
        bundle: &bundles.Bundle{
            ID: "b1", Type: "session_import",
            ExpiresAt: time.Now().Add(24 * time.Hour),
        },
    }
    s := &RecordedLoginStrategy{Bundles: store}
    _, err := s.Authenticate(context.Background(), AuthConfig{
        BundleID: "b1", CustomerID: "c1", ProjectID: "p1",
    })
    if err == nil {
        t.Fatal("expected wrong-type rejection")
    }
}

func TestRecordedLogin_Expired(t *testing.T) {
    store := &recordedFakeStore{
        bundle: &bundles.Bundle{
            ID: "b1", Type: "recorded_login",
            ExpiresAt: time.Now().Add(-time.Hour),
        },
    }
    s := &RecordedLoginStrategy{Bundles: store}
    _, err := s.Authenticate(context.Background(), AuthConfig{
        BundleID: "b1", CustomerID: "c1", ProjectID: "p1",
    })
    if err == nil {
        t.Fatal("expected expired rejection")
    }
}

func TestRecordedLogin_LoadError(t *testing.T) {
    store := &recordedFakeStore{err: errors.New("db error")}
    s := &RecordedLoginStrategy{Bundles: store}
    _, err := s.Authenticate(context.Background(), AuthConfig{
        BundleID: "b1", CustomerID: "c1", ProjectID: "p1",
    })
    if err == nil {
        t.Fatal("expected load error")
    }
}

func TestRecordedLogin_RefreshErrors(t *testing.T) {
    s := &RecordedLoginStrategy{}
    _, err := s.Refresh(context.Background(), nil, AuthConfig{})
    if err == nil {
        t.Fatal("expected refresh to error in one-shot mode")
    }
}
```

- [ ] **Step 2: Run**

```
go test ./internal/authbroker/ -run TestRecordedLogin -v
```

Expected: 5 PASS lines.

- [ ] **Step 3: Commit**

```
git add internal/authbroker/recorded_login_strategy_test.go
git commit -m "test(authbroker): cover RecordedLoginStrategy authenticate paths"
```

### Task D.3: Run all tests + push

```
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-recording
go test ./internal/...
git push
```

Expected: PASS.

### Task D.4: Build, deploy, open PR

This is the controller's task — apply migration 046 to production, build + deploy controlplane, open the GitHub PR.

```
rsync -az --delete --exclude .git --exclude '*.test' --exclude '.worktrees' \
  internal migrations pkg rules scripts cmd Dockerfile go.mod go.sum customer-sdks \
  okyay@77.42.34.174:/tmp/sentinelcore-src/

ssh okyay@77.42.34.174 "cp /tmp/sentinelcore-src/migrations/046_dast_bundle_recording_metadata.up.sql /opt/sentinelcore/migrations/ && \
  docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -f /migrations/046_dast_bundle_recording_metadata.up.sql 2>&1 | tail -5"

ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build --no-cache -t sentinelcore/controlplane:rec-prd --build-arg SERVICE=controlplane . 2>&1 | tail -3 && \
  docker tag sentinelcore/controlplane:rec-prd sentinelcore/controlplane:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d --force-recreate controlplane 2>&1 | tail -3"

curl -s -o /dev/null -w 'healthz: %{http_code}\nreadyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/healthz

git push
gh pr create --base phase2/api-dast --title "feat(dast): recording subsystem (CLI + RecordedLoginStrategy one-shot) [plan #3/6]" --body ...
```

PR D complete.

---

## Self-review

### Spec coverage

| Spec section | Implementing task |
|--------------|-------------------|
| §5.1 Sandboxed Chrome | B.1 (chromedp options: disable-extensions, disable Autofill, no first-run) |
| §5.2 Action capture | DEFERRED to Plan #4 (only cookies + final URL captured here) |
| §5.3 Credentials never stored | Trivially satisfied — recorder doesn't capture form-fill values |
| §5.5 Recorder output bundle format | C.2 (uploadBundle constructs the JSON shape) + A.2 (RecordingMetadata persistence) |
| §5.6 Browser fingerprint | B.1 (UA captured), A.2 (persisted as recording_metadata.browser_user_agent) |
| §6.1 One-shot mode | D.1 (RecordedLoginStrategy returns captured session directly; refresh errors) |
| §8.2 RecordedLoginStrategy | D.1 |

### Spec sections explicitly deferred to Plan #4

- §5.2 action list capture
- §5.4 server-side validation of action list
- §6.2-6.7 replay engine, pre-flight checks, post-state assertion, principal binding, rate limit, kill switch
- §8.2 RecordedLoginStrategy.Refresh automatable mode

### Type consistency

- `recording.RecordedSession` defined in B.1; consumed by `cmd/cli/dast_record.go` in C.2
- `bundles.RecordingMetadata` defined in A.2; consumed by uploadBundle (mirror struct) in C.2 and read in D.1 via b.RecordingMetadata
- `RecordedLoginStrategy` defined in D.1; tested in D.2

No drift.

---

## Execution handoff

Plan #3 saved to `docs/superpowers/plans/2026-05-04-dast-recording-subsystem.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch fresh subagents per PR; review between PRs.

**2. Inline Execution** — Continue in this session via executing-plans.
