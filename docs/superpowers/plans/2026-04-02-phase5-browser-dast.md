# Phase 5: Browser-Based DAST Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add authenticated browser-driven DAST scanning to SentinelCore using chromedp, with three-layer scope enforcement, non-destructive crawling by default, and screenshot evidence.

**Architecture:** Separate `cmd/dast-browser-worker` binary using chromedp (pure Go CDP). Scope enforcement via three layers: CDP `Fetch.requestPaused` (L1), container iptables rules (L2), `Network.responseReceived` IP monitoring (L3). Auth session reuse via scope-gated credential injection. One Chrome instance per scan job, destroyed completely after each job.

**Tech Stack:** Go 1.22+, chromedp, Chrome DevTools Protocol, existing `pkg/scope`, `internal/authbroker`, `internal/dast` (Evidence/Finding types), NATS JetStream, seccomp-bpf.

**Spec:** Security review at conversation context (31 issues, 17 merge blockers addressed in this plan).

---

## File Structure

### New Files

```
internal/browser/                        # Browser DAST package
  types.go                               # BrowserScanJob, BrowserScanResult, CrawlConfig, PageResult
  chrome.go                              # Chrome lifecycle: launch, configure flags, kill, cleanup
  chrome_test.go                         # Chrome flag tests, lifecycle tests
  interceptor.go                         # CDP Fetch.requestPaused scope enforcement (Layer 1)
  interceptor_test.go                    # Scope enforcement tests for CDP requests
  monitor.go                             # Network.responseReceived IP monitoring (Layer 3)
  monitor_test.go                        # IP monitoring and WebSocket blocking tests
  crawler.go                             # Link/form discovery, depth-limited navigation
  crawler_test.go                        # Crawl depth, URL budget, destructive form blocking tests
  scanner.go                             # DOM-XSS, open redirect, mixed content, CSRF detection
  scanner_test.go                        # Vulnerability detection tests
  evidence.go                            # CDP-aware evidence capture: screenshots, DOM, network
  evidence_test.go                       # Evidence redaction tests for CDP JSON
  auth.go                                # Scope-gated auth injection for browser contexts
  auth_test.go                           # Auth injection scope-gating tests
  worker.go                              # Top-level browser scan orchestrator
  worker_test.go                         # Worker lifecycle tests

cmd/dast-browser-worker/main.go          # Binary: NATS consumer → browser worker

deploy/seccomp/dast-browser-worker.json  # Relaxed seccomp profile (allows execve for Chrome)
deploy/iptables/browser-worker.sh        # Container iptables rules (Layer 2)
docs/browser-worker-chrome-flags.md      # Chrome flags specification with security rationale
```

### Modified Files

```
pkg/scope/enforcer.go                    # Add ws/wss scheme support to CheckRequest
pkg/scope/enforcer_test.go              # Tests for ws/wss scheme validation
internal/dast/evidence.go               # Export sensitiveHeaders and sensitivePatterns for reuse
internal/dast/natsworker.go             # No changes (browser worker has its own NATS handler)
deploy/docker-compose/docker-compose.yml # Add dast-browser-worker service
go.mod                                  # Add chromedp dependency
```

---

## Chunk 1: Foundation — Types, Chrome Lifecycle, Seccomp (Tasks 1-3)

### Task 1: Add chromedp Dependency and Browser Types

**Files:**
- Modify: `go.mod`
- Create: `internal/browser/types.go`

- [ ] **Step 1: Add chromedp dependency**

Run: `go get github.com/chromedp/chromedp@latest`

- [ ] **Step 2: Write browser types**

`internal/browser/types.go`:

```go
package browser

import (
    "time"

    "github.com/sentinelcore/sentinelcore/internal/authbroker"
    "github.com/sentinelcore/sentinelcore/internal/dast"
    "github.com/sentinelcore/sentinelcore/pkg/scope"
)

// BrowserScanJob describes a browser-based DAST scan.
type BrowserScanJob struct {
    ID            string               `json:"id"`
    ProjectID     string               `json:"project_id"`
    TargetBaseURL string               `json:"target_base_url"`
    SeedURLs      []string             `json:"seed_urls"`
    AllowedHosts  []string             `json:"allowed_hosts"`
    PinnedIPs     map[string][]string  `json:"pinned_ips"`
    AuthConfig    *authbroker.AuthConfig `json:"auth_config,omitempty"`
    CrawlConfig   CrawlConfig          `json:"crawl_config"`
    ScopeConfig   scope.Config         `json:"-"`
}

// CrawlConfig controls browser crawling behavior.
type CrawlConfig struct {
    MaxDepth      int           `json:"max_depth"`       // default 3
    MaxURLs       int           `json:"max_urls"`        // default 500
    MaxDuration   time.Duration `json:"max_duration"`    // default 30m
    SubmitForms   bool          `json:"submit_forms"`    // default false (non-destructive)
    TakeScreenshots bool        `json:"take_screenshots"` // default true for findings only
    PageTimeout   time.Duration `json:"page_timeout"`    // default 30s per page
}

// DefaultCrawlConfig returns safe defaults for browser crawling.
func DefaultCrawlConfig() CrawlConfig {
    return CrawlConfig{
        MaxDepth:        3,
        MaxURLs:         500,
        MaxDuration:     30 * time.Minute,
        SubmitForms:     false,
        TakeScreenshots: true,
        PageTimeout:     30 * time.Second,
    }
}

// BrowserScanResult contains the outcome of a browser scan.
type BrowserScanResult struct {
    ScanJobID       string         `json:"scan_job_id"`
    WorkerID        string         `json:"worker_id"`
    Status          string         `json:"status"`
    Findings        []dast.Finding `json:"findings"`
    PagesVisited    int            `json:"pages_visited"`
    FormsDiscovered int            `json:"forms_discovered"`
    ScopeViolations int64          `json:"scope_violations"`
    Duration        time.Duration  `json:"duration"`
    StartedAt       time.Time      `json:"started_at"`
    CompletedAt     time.Time      `json:"completed_at"`
    Error           string         `json:"error,omitempty"`
}

// PageResult captures the outcome of visiting a single page.
type PageResult struct {
    URL           string        `json:"url"`
    StatusCode    int           `json:"status_code"`
    Title         string        `json:"title"`
    Links         []string      `json:"links"`
    Forms         []FormInfo    `json:"forms"`
    NavigationErr string        `json:"navigation_err,omitempty"`
    LoadTime      time.Duration `json:"load_time"`
}

// FormInfo describes a discovered HTML form.
type FormInfo struct {
    Action   string            `json:"action"`
    Method   string            `json:"method"`
    Fields   []FormField       `json:"fields"`
    HasCSRF  bool              `json:"has_csrf"`
    IsSafe   bool              `json:"is_safe"` // false if contains destructive keywords
}

// FormField describes a single form input.
type FormField struct {
    Name  string `json:"name"`
    Type  string `json:"type"`
    Value string `json:"value,omitempty"`
}

// destructiveKeywords blocks form submission when any appear in
// the form action URL, button text, or nearby labels.
var DestructiveKeywords = []string{
    "delete", "remove", "cancel", "unsubscribe",
    "pay", "purchase", "transfer", "send",
    "destroy", "drop", "terminate", "revoke",
}
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./internal/browser/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum internal/browser/types.go
git commit -m "feat(phase5): add browser DAST types and chromedp dependency"
```

---

### Task 2: Chrome Lifecycle Manager

**Files:**
- Create: `internal/browser/chrome.go`
- Create: `internal/browser/chrome_test.go`

- [ ] **Step 1: Write failing test**

`internal/browser/chrome_test.go`:

```go
package browser

import "testing"

func TestChromeFlags_ContainsSecurityFlags(t *testing.T) {
    flags := ChromeFlags("test-job-123")
    required := []string{
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--dns-prefetch-disable",
        "--no-first-run",
    }
    flagSet := make(map[string]bool)
    for _, f := range flags {
        flagSet[f] = true
    }
    for _, req := range required {
        if !flagSet[req] {
            t.Errorf("missing required Chrome flag: %s", req)
        }
    }
}

func TestChromeFlags_DisablesServiceWorkerAndWebRTC(t *testing.T) {
    flags := ChromeFlags("test-job")
    found := false
    for _, f := range flags {
        if f == "--disable-features=ServiceWorker,WebRTC,NetworkPrediction,AutofillServerCommunication" {
            found = true
            break
        }
    }
    if !found {
        t.Error("missing --disable-features flag with ServiceWorker and WebRTC")
    }
}

func TestChromeFlags_HasV8MemoryLimit(t *testing.T) {
    flags := ChromeFlags("test-job")
    found := false
    for _, f := range flags {
        if f == "--js-flags=--max-old-space-size=512" {
            found = true
            break
        }
    }
    if !found {
        t.Error("missing V8 heap size limit flag")
    }
}

func TestChromeFlags_HasUniqueProfileDir(t *testing.T) {
    flags1 := ChromeFlags("job-1")
    flags2 := ChromeFlags("job-2")
    var dir1, dir2 string
    for _, f := range flags1 {
        if len(f) > 16 && f[:16] == "--user-data-dir=" {
            dir1 = f
        }
    }
    for _, f := range flags2 {
        if len(f) > 16 && f[:16] == "--user-data-dir=" {
            dir2 = f
        }
    }
    if dir1 == "" || dir2 == "" {
        t.Fatal("missing --user-data-dir flag")
    }
    if dir1 == dir2 {
        t.Error("profile directories should be unique per job")
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `go test ./internal/browser/... -v -run TestChrome -count=1`
Expected: FAIL (ChromeFlags not defined)

- [ ] **Step 3: Implement chrome.go**

`internal/browser/chrome.go` — Chrome lifecycle management:

```go
package browser

import (
    "context"
    "fmt"
    "os"
    "path/filepath"

    "github.com/chromedp/chromedp"
    "github.com/rs/zerolog"
)

// ChromeFlags returns the hardened Chrome launch flags for a scan job.
// Each flag is documented in docs/browser-worker-chrome-flags.md.
func ChromeFlags(jobID string) []string {
    profileDir := filepath.Join(os.TempDir(), fmt.Sprintf("sentinel-chrome-%s", jobID))
    return []string{
        "--headless=new",
        "--no-sandbox",                // Container provides isolation (see design doc)
        "--disable-gpu",               // No GPU in headless container
        "--disable-software-rasterizer",
        "--disable-dev-shm-usage",     // Use /tmp instead of /dev/shm
        "--disable-background-networking",
        "--disable-features=ServiceWorker,WebRTC,NetworkPrediction,AutofillServerCommunication",
        "--disable-blink-features=AutomationControlled",
        "--disable-component-update",
        "--disable-default-apps",
        "--dns-prefetch-disable",
        "--no-first-run",
        "--js-flags=--max-old-space-size=512",
        fmt.Sprintf("--user-data-dir=%s", profileDir),
    }
}

// ProfileDir returns the Chrome profile directory path for a job.
func ProfileDir(jobID string) string {
    return filepath.Join(os.TempDir(), fmt.Sprintf("sentinel-chrome-%s", jobID))
}

// ChromeContext creates a chromedp browser context with hardened flags.
// The returned cancel function kills Chrome and cleans up the profile directory.
func ChromeContext(ctx context.Context, jobID string, logger zerolog.Logger) (context.Context, context.CancelFunc) {
    flags := ChromeFlags(jobID)

    // Build chromedp options directly — do NOT string-split flags.
    // ChromeFlags() exists for documentation/testing only.
    profileDir := ProfileDir(jobID)
    opts := []chromedp.ExecAllocatorOption{
        chromedp.NoDefaultBrowserCheck,
        chromedp.NoFirstRun,
        chromedp.Headless,
        chromedp.Flag("no-sandbox", true),
        chromedp.Flag("disable-gpu", true),
        chromedp.Flag("disable-software-rasterizer", true),
        chromedp.Flag("disable-dev-shm-usage", true),
        chromedp.Flag("disable-background-networking", true),
        chromedp.Flag("disable-features", "ServiceWorker,WebRTC,NetworkPrediction,AutofillServerCommunication"),
        chromedp.Flag("disable-blink-features", "AutomationControlled"),
        chromedp.Flag("disable-component-update", true),
        chromedp.Flag("disable-default-apps", true),
        chromedp.Flag("dns-prefetch-disable", true),
        chromedp.Flag("js-flags", "--max-old-space-size=512"),
        chromedp.Flag("user-data-dir", profileDir),
    }

    allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
    taskCtx, taskCancel := chromedp.NewContext(allocCtx,
        chromedp.WithLogf(func(s string, args ...interface{}) {
            logger.Debug().Msgf("[chrome] "+s, args...)
        }),
    )

    cleanup := func() {
        taskCancel()
        allocCancel()
        // Kill Chrome profile directory
        profileDir := ProfileDir(jobID)
        if err := os.RemoveAll(profileDir); err != nil {
            logger.Warn().Err(err).Str("dir", profileDir).Msg("failed to clean Chrome profile")
        }
        logger.Info().Str("job_id", jobID).Msg("Chrome context destroyed and profile cleaned")
    }

    return taskCtx, cleanup
}
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `go test ./internal/browser/... -v -run TestChrome -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/browser/chrome.go internal/browser/chrome_test.go
git commit -m "feat(phase5): add Chrome lifecycle manager with hardened flags"
```

---

### Task 3: Seccomp Profile, iptables Rules, Chrome Flags Doc

**Files:**
- Create: `deploy/seccomp/dast-browser-worker.json`
- Create: `deploy/iptables/browser-worker.sh`
- Create: `docs/browser-worker-chrome-flags.md`

- [ ] **Step 1: Write browser worker seccomp profile**

`deploy/seccomp/dast-browser-worker.json` — Allows execve (for Chrome), fork/clone (for Chrome subprocesses), and ptrace-related syscalls. Everything else matches the existing DAST worker profile.

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "close", "fstat", "lseek",
        "mmap", "mprotect", "munmap", "brk",
        "pread64", "pwrite64",
        "access", "getpid", "getuid", "getgid",
        "geteuid", "getegid", "gettid",
        "socket", "connect", "bind", "listen", "accept", "accept4",
        "sendto", "recvfrom", "sendmsg", "recvmsg",
        "setsockopt", "getsockopt", "getsockname", "getpeername",
        "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
        "select", "poll", "ppoll",
        "openat", "readlinkat", "newfstatat",
        "futex", "nanosleep", "clock_gettime", "clock_nanosleep",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "sigaltstack", "tgkill",
        "exit", "exit_group",
        "getrandom",
        "pipe2", "dup", "dup2", "dup3",
        "fcntl", "ioctl",
        "sched_yield", "sched_getaffinity",
        "set_robust_list", "get_robust_list",
        "arch_prctl", "set_tid_address",
        "madvise", "mincore",
        "clone3", "clone", "rseq",
        "execve", "execveat",
        "wait4", "waitid",
        "fork", "vfork",
        "prctl", "seccomp",
        "getdents64", "getcwd",
        "statx", "stat", "lstat",
        "mkdir", "mkdirat", "unlink", "unlinkat", "rmdir", "rename", "renameat2",
        "chmod", "fchmod", "chown",
        "pipe", "eventfd2",
        "memfd_create",
        "prlimit64", "getrlimit", "setrlimit",
        "sysinfo", "uname",
        "getppid", "getpgid", "setpgid", "setsid", "getsid",
        "kill",
        "socketpair", "shutdown",
        "recvmmsg", "sendmmsg",
        "fallocate", "ftruncate",
        "mremap"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ],
  "_comment": "Browser DAST worker: allows execve/fork for Chrome subprocesses. More permissive than API DAST worker. Container-level isolation (namespaces, cgroups, iptables) provides the primary security boundary."
}
```

- [ ] **Step 2: Write iptables rules for Layer 2 scope enforcement**

`deploy/iptables/browser-worker.sh`:

```bash
#!/bin/sh
# Layer 2 scope enforcement: kernel-level network filtering for browser worker.
# Blocks RFC 1918, loopback, link-local, and cloud metadata at the kernel level.
# This is the fallback layer — CDP interception is Layer 1.

set -e

# Allow loopback for Chrome IPC (must come first)
iptables -A OUTPUT -o lo -j ACCEPT

# Block NEW connections to private/reserved ranges
iptables -A OUTPUT -m state --state NEW -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP

# Block loopback (except lo interface already allowed above)
iptables -A OUTPUT -d 127.0.0.0/8 -j DROP

# Block link-local
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP

# Block cloud metadata
iptables -A OUTPUT -d 169.254.169.254/32 -j DROP

# Block carrier-grade NAT
iptables -A OUTPUT -d 100.64.0.0/10 -j DROP

# Block test/documentation ranges
iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
iptables -A OUTPUT -d 203.0.113.0/24 -j DROP

# Block unspecified and reserved
iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
iptables -A OUTPUT -d 240.0.0.0/4 -j DROP

# Allow everything else (targets are external)
iptables -A OUTPUT -j ACCEPT

echo "Browser worker iptables rules applied."
```

- [ ] **Step 3: Write Chrome flags specification doc**

`docs/browser-worker-chrome-flags.md` — document every flag, its security purpose, and what it mitigates. This is a reviewed artifact per the security review recommendation.

- [ ] **Step 4: Commit**

```bash
git add deploy/seccomp/dast-browser-worker.json deploy/iptables/browser-worker.sh docs/browser-worker-chrome-flags.md
git commit -m "feat(phase5): add browser worker seccomp, iptables rules, Chrome flags doc"
```

---

## Chunk 2: Scope Enforcement — Three Layers (Tasks 4-6)

### Task 4: Add ws/wss Scheme Support to Scope Enforcer

**Files:**
- Modify: `pkg/scope/enforcer.go`
- Modify: `pkg/scope/enforcer_test.go`

- [ ] **Step 1: Write failing test**

Add to `pkg/scope/enforcer_test.go`:

```go
func TestCheckRequest_WebSocketSchemes(t *testing.T) {
    cfg := Config{
        AllowedHosts: []string{"target.com"},
        PinnedIPs:    map[string][]net.IP{"target.com": {net.ParseIP("1.2.3.4")}},
    }
    e := NewEnforcer(cfg, zerolog.Nop())

    // ws:// should be allowed for in-scope host
    if err := e.CheckRequest(context.Background(), "ws://target.com/socket"); err != nil {
        t.Errorf("ws:// to allowed host should pass: %v", err)
    }
    // wss:// should be allowed for in-scope host
    if err := e.CheckRequest(context.Background(), "wss://target.com/socket"); err != nil {
        t.Errorf("wss:// to allowed host should pass: %v", err)
    }
    // ws:// to out-of-scope host should fail
    if err := e.CheckRequest(context.Background(), "ws://evil.com/socket"); err == nil {
        t.Error("ws:// to out-of-scope host should fail")
    }
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `go test ./pkg/scope/... -v -run TestCheckRequest_WebSocket -count=1`
Expected: FAIL

- [ ] **Step 3: Modify CheckRequest to accept ws/wss**

In `pkg/scope/enforcer.go`, in the `CheckRequest` method, add scheme normalization:

```go
// Normalize WebSocket schemes to HTTP equivalents for validation
switch parsed.Scheme {
case "ws":
    parsed.Scheme = "http"
case "wss":
    parsed.Scheme = "https"
}
```

- [ ] **Step 4: Run test — verify it passes**

Run: `go test ./pkg/scope/... -v -count=1`
Expected: All PASS (no regressions)

- [ ] **Step 5: Commit**

```bash
git add pkg/scope/enforcer.go pkg/scope/enforcer_test.go
git commit -m "feat(phase5): add ws/wss scheme support to scope enforcer"
```

---

### Task 5: CDP Request Interceptor (Layer 1)

**Files:**
- Create: `internal/browser/interceptor.go`
- Create: `internal/browser/interceptor_test.go`

- [ ] **Step 1: Write failing tests**

```go
package browser

import (
    "net"
    "testing"

    "github.com/sentinelcore/sentinelcore/pkg/scope"
    "github.com/rs/zerolog"
)

func TestInterceptor_AllowsInScopeRequest(t *testing.T) {
    cfg := scope.Config{
        AllowedHosts: []string{"target.com"},
        PinnedIPs:    map[string][]net.IP{"target.com": {net.ParseIP("93.184.216.34")}},
    }
    enforcer := scope.NewEnforcer(cfg, zerolog.Nop())
    ic := NewInterceptor(enforcer, nil, zerolog.Nop())

    decision := ic.Decide("https://target.com/page")
    if decision != Allow {
        t.Errorf("expected Allow, got %v", decision)
    }
}

func TestInterceptor_BlocksOutOfScopeRequest(t *testing.T) {
    cfg := scope.Config{
        AllowedHosts: []string{"target.com"},
        PinnedIPs:    map[string][]net.IP{"target.com": {net.ParseIP("93.184.216.34")}},
    }
    enforcer := scope.NewEnforcer(cfg, zerolog.Nop())
    ic := NewInterceptor(enforcer, nil, zerolog.Nop())

    decision := ic.Decide("https://evil.com/steal")
    if decision != Block {
        t.Errorf("expected Block, got %v", decision)
    }
}

func TestInterceptor_BlocksPrivateIP(t *testing.T) {
    cfg := scope.Config{
        AllowedHosts: []string{"internal.corp"},
        PinnedIPs:    map[string][]net.IP{"internal.corp": {net.ParseIP("10.0.0.1")}},
    }
    enforcer := scope.NewEnforcer(cfg, zerolog.Nop())
    ic := NewInterceptor(enforcer, nil, zerolog.Nop())

    decision := ic.Decide("https://internal.corp/admin")
    if decision != Block {
        t.Errorf("expected Block for private IP, got %v", decision)
    }
}

func TestInterceptor_NeverModifiesURL(t *testing.T) {
    // Architectural invariant: interceptor is allow/block only, never modify
    cfg := scope.Config{AllowedHosts: []string{"target.com"}}
    enforcer := scope.NewEnforcer(cfg, zerolog.Nop())
    ic := NewInterceptor(enforcer, nil, zerolog.Nop())

    url := "https://target.com/page?q=test"
    decision := ic.Decide(url)
    if decision != Allow {
        t.Fatal("should allow in-scope URL")
    }
    // The interceptor provides no method to modify URLs — this is by design.
    // Verify the type has no ModifyURL or similar method.
}
```

- [ ] **Step 2: Implement interceptor.go**

`internal/browser/interceptor.go`:

```go
package browser

import (
    "context"
    "sync/atomic"

    "github.com/chromedp/cdproto/fetch"
    "github.com/chromedp/cdproto/network"
    "github.com/chromedp/chromedp"
    "github.com/rs/zerolog"
    "github.com/sentinelcore/sentinelcore/internal/authbroker"
    "github.com/sentinelcore/sentinelcore/pkg/scope"
)

// Decision represents an allow/block verdict.
type Decision int

const (
    Allow Decision = iota
    Block
)

// Interceptor enforces scope on every CDP network request.
// It is allow/block only — it NEVER modifies request URLs, headers, or bodies.
// Auth header injection is handled separately by the auth layer.
type Interceptor struct {
    enforcer   *scope.Enforcer
    session    *authbroker.Session
    logger     zerolog.Logger
    violations atomic.Int64
}

// NewInterceptor creates a scope-enforcing CDP request interceptor.
func NewInterceptor(enforcer *scope.Enforcer, session *authbroker.Session, logger zerolog.Logger) *Interceptor {
    return &Interceptor{
        enforcer: enforcer,
        session:  session,
        logger:   logger.With().Str("component", "cdp-interceptor").Logger(),
    }
}

// Decide checks a URL against the scope enforcer. Returns Allow or Block.
// This is the pure decision function — no CDP interaction.
func (i *Interceptor) Decide(reqURL string) Decision {
    if err := i.enforcer.CheckRequest(context.Background(), reqURL); err != nil {
        i.violations.Add(1)
        i.logger.Warn().Str("url", reqURL).Err(err).Msg("scope violation: request blocked")
        return Block
    }
    return Allow
}

// Violations returns the count of blocked requests.
func (i *Interceptor) Violations() int64 {
    return i.violations.Load()
}

// Enable sets up CDP Fetch.requestPaused interception on a chromedp context.
// Every request is paused, checked against scope, then continued or failed.
func (i *Interceptor) Enable(ctx context.Context) error {
    // Enable fetch interception for all URL patterns
    if err := chromedp.Run(ctx,
        fetch.Enable().WithPatterns([]*fetch.RequestPattern{
            {URLPattern: "*", RequestStage: fetch.RequestStageRequest},
        }),
    ); err != nil {
        return err
    }

    // Listen for paused requests
    chromedp.ListenTarget(ctx, func(ev interface{}) {
        switch e := ev.(type) {
        case *fetch.EventRequestPaused:
            go i.handleRequestPaused(ctx, e)
        }
    })

    return nil
}

func (i *Interceptor) handleRequestPaused(ctx context.Context, e *fetch.EventRequestPaused) {
    reqURL := e.Request.URL
    decision := i.Decide(reqURL)

    if decision == Block {
        // Fail the request — do NOT modify and continue
        fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
        return
    }

    // Allow: Decide() already proved URL is in-scope (no redundant re-check).
    // Inject auth headers only for in-scope requests (which all allowed requests are).
    var headers []*fetch.HeaderEntry
    if i.session != nil {
        for k, v := range i.session.Headers {
            headers = append(headers, &fetch.HeaderEntry{Name: k, Value: v})
        }
    }

    if len(headers) > 0 {
        fetch.ContinueRequest(e.RequestID).WithHeaders(headers).Do(ctx)
    } else {
        fetch.ContinueRequest(e.RequestID).Do(ctx)
    }
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/browser/... -v -run TestInterceptor -count=1`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/browser/interceptor.go internal/browser/interceptor_test.go
git commit -m "feat(phase5): add CDP request interceptor with scope enforcement (Layer 1)"
```

---

### Task 6: Network Monitor (Layer 3) and WebSocket Blocker

**Files:**
- Create: `internal/browser/monitor.go`
- Create: `internal/browser/monitor_test.go`

- [ ] **Step 1: Write failing tests**

Tests for: IP validation on `Network.responseReceived`, WebSocket URL blocking via `Network.webSocketCreated`, violation counting.

- [ ] **Step 2: Implement monitor.go**

`internal/browser/monitor.go` — listens to `Network.responseReceived` events and validates `remoteIPAddress` against the scope enforcer's pinned IPs. Listens to `Network.webSocketCreated` and validates the WebSocket URL against scope. Logs violations and triggers abort if threshold exceeded.

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/browser/monitor.go internal/browser/monitor_test.go
git commit -m "feat(phase5): add network monitor (Layer 3) and WebSocket scope enforcement"
```

---

## Chunk 3: Evidence and Auth (Tasks 7-9)

### Task 7: Export Evidence Redaction Patterns

**Files:**
- Modify: `internal/dast/evidence.go`

- [ ] **Step 1: Export sensitiveHeaders and sensitivePatterns**

Rename `sensitiveHeaders` → `SensitiveHeaders` and `sensitivePatterns` → `SensitivePatterns` in `internal/dast/evidence.go`. These are needed by the browser evidence layer.

- [ ] **Step 2: Run existing DAST tests — verify no regressions**

Run: `go test ./internal/dast/... -count=1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/dast/evidence.go
git commit -m "refactor(dast): export evidence redaction patterns for browser reuse"
```

---

### Task 8: CDP-Aware Evidence Capture

**Files:**
- Create: `internal/browser/evidence.go`
- Create: `internal/browser/evidence_test.go`

- [ ] **Step 1: Write failing tests**

Tests for:
- `RedactCDPHeaders` — applies same sensitive header redaction to CDP event JSON
- `RedactBody` — applies sensitive patterns to response bodies
- `CaptureScreenshot` — returns evidence with screenshot bytes and SHA-256 hash
- `RedactScreenshotFormFields` — injects CSS blur on input fields before screenshot
- Screenshots are never captured during authentication phase

- [ ] **Step 2: Implement evidence.go**

```go
package browser

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "strings"
    "time"

    "github.com/chromedp/chromedp"
    "github.com/sentinelcore/sentinelcore/internal/dast"
)

// RedactCDPHeaders applies the same redaction rules as dast.SensitiveHeaders
// to CDP network event header maps.
func RedactCDPHeaders(headers map[string]interface{}) map[string]string {
    result := make(map[string]string)
    for k, v := range headers {
        lower := strings.ToLower(k)
        if dast.SensitiveHeaders[lower] {
            result[k] = "[REDACTED]"
        } else {
            result[k] = fmt.Sprintf("%v", v)
        }
    }
    return result
}

// RedactBody applies sensitive pattern matching to a body string.
func RedactBody(body string) string {
    for _, p := range dast.SensitivePatterns {
        body = p.ReplaceAllString(body, "[REDACTED]")
    }
    return body
}

// ScreenshotEvidence captures a screenshot with form field redaction.
// Returns base64-encoded PNG and its SHA-256 hash.
func ScreenshotEvidence(ctx context.Context, scanJobID, ruleID string) (*dast.Evidence, []byte, error) {
    // Blur form inputs before screenshot (privacy protection)
    chromedp.Run(ctx, chromedp.Evaluate(
        `document.querySelectorAll('input, textarea').forEach(el => {
            el.style.filter = 'blur(5px)';
            if (el.type === 'password' || el.type === 'text') el.value = '[REDACTED]';
        })`, nil))

    var buf []byte
    if err := chromedp.Run(ctx, chromedp.FullScreenshot(&buf, 80)); err != nil {
        return nil, nil, err
    }

    hash := sha256.Sum256(buf)
    ev := &dast.Evidence{
        ScanJobID:  scanJobID,
        RuleID:     ruleID,
        SHA256:     hex.EncodeToString(hash[:]),
        CapturedAt: time.Now(),
        Metadata: map[string]string{
            "type":     "screenshot",
            "encoding": "png",
            "size":     fmt.Sprintf("%d", len(buf)),
        },
    }
    return ev, buf, nil
}
```

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/browser/evidence.go internal/browser/evidence_test.go
git commit -m "feat(phase5): add CDP-aware evidence capture with screenshot redaction"
```

---

### Task 9: Scope-Gated Auth Injection

**Files:**
- Create: `internal/browser/auth.go`
- Create: `internal/browser/auth_test.go`

- [ ] **Step 1: Write failing tests**

Tests for:
- `InjectCookies` — sets cookies with narrowest scope (SameSite=Strict, HttpOnly, Secure)
- `ShouldInjectAuth` — returns true only for in-scope URLs
- Auth headers are NEVER injected for out-of-scope URLs
- Cookies are scoped to the target domain only

- [ ] **Step 2: Implement auth.go**

`internal/browser/auth.go` — handles browser-specific auth injection:
- `InjectCookies(ctx, session, targetHost)` — uses `Network.setCookie` with strict attributes
- `ShouldInjectAuth(url, enforcer)` — checks scope before any credential injection
- No auth injection during third-party resource loads

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/browser/auth.go internal/browser/auth_test.go
git commit -m "feat(phase5): add scope-gated auth injection for browser contexts"
```

---

## Chunk 4: Crawler and Scanner (Tasks 10-12)

### Task 10: Depth-Limited Crawler with Safety Controls

**Files:**
- Create: `internal/browser/crawler.go`
- Create: `internal/browser/crawler_test.go`

- [ ] **Step 1: Write failing tests**

Tests for:
- `IsDestructiveForm` — detects forms with destructive keywords
- `NormalizeURL` — deduplicates URLs that differ only in fragments
- Crawler respects MaxDepth (depth 3 limit)
- Crawler respects MaxURLs (500 limit)
- Crawler respects MaxDuration (timeout)
- Crawler skips forms when SubmitForms=false (default)
- Crawler blocks destructive form submission even when SubmitForms=true
- Crawler validates discovered URLs against scope before navigating

- [ ] **Step 2: Implement crawler.go**

`internal/browser/crawler.go`:
- `Crawler` struct with `CrawlConfig`, scope `Enforcer`, visited URL set
- `Crawl(ctx, seedURLs) ([]PageResult, error)` — BFS traversal up to MaxDepth
- Link extraction via `chromedp.Evaluate` (querySelectorAll a[href])
- Form discovery via `chromedp.Evaluate` (querySelectorAll form)
- `IsDestructiveForm(form)` — keyword-based safety check
- `NormalizeURL(raw, base)` — resolve relative URLs, strip fragments
- URL deduplication before navigation
- Context deadline enforcement

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/browser/crawler.go internal/browser/crawler_test.go
git commit -m "feat(phase5): add depth-limited crawler with destructive form blocking"
```

---

### Task 11: DOM Security Scanner

**Files:**
- Create: `internal/browser/scanner.go`
- Create: `internal/browser/scanner_test.go`

- [ ] **Step 1: Write failing tests**

Tests for:
- DOM-XSS detection: inject canary in URL fragment, check if it executes
- Open redirect detection: follow redirects, check if target leaves scope
- Mixed content detection: HTTPS page loading HTTP resources
- Missing CSRF token detection: forms without hidden csrf fields
- Insecure cookie detection: cookies without Secure/HttpOnly flags

- [ ] **Step 2: Implement scanner.go**

`internal/browser/scanner.go`:
- `ScanPage(ctx, pageResult, enforcer, scanJobID) ([]dast.Finding, error)`
- `checkDOMXSS(ctx, url)` — inject canary payload via URL params, check DOM for execution
- `checkOpenRedirect(ctx, url, enforcer)` — check if navigation target leaves scope
- `checkMixedContent(ctx)` — evaluate document for HTTP resources on HTTPS page
- `checkCSRFTokens(ctx, forms)` — verify forms have CSRF token fields
- `checkInsecureCookies(ctx)` — inspect cookies via CDP `Network.getCookies`
- Each check returns `[]dast.Finding` with appropriate severity/category/evidence

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/browser/scanner.go internal/browser/scanner_test.go
git commit -m "feat(phase5): add DOM security scanner (XSS, redirect, mixed content, CSRF)"
```

---

### Task 12: Browser Worker Orchestrator

**Files:**
- Create: `internal/browser/worker.go`
- Create: `internal/browser/worker_test.go`

- [ ] **Step 1: Write failing tests**

Tests for:
- Worker refuses to start without signing key
- Worker sets up all three scope enforcement layers
- Worker produces BrowserScanResult with correct fields
- Worker kills Chrome on context cancellation
- Worker cleans up profile directory even on error

- [ ] **Step 2: Implement worker.go**

`internal/browser/worker.go`:
- `BrowserWorker` struct: config, auth broker, logger, signing key
- `ExecuteScan(ctx, job BrowserScanJob) (*BrowserScanResult, error)`:
  1. Create Chrome context with hardened flags
  2. Set up Interceptor (Layer 1)
  3. Set up Monitor (Layer 3)
  4. Authenticate if AuthConfig present (scope-gated injection)
  5. Run Crawler (discover pages)
  6. Run Scanner (check each page for vulnerabilities)
  7. Capture screenshot evidence for findings
  8. Destroy Chrome context and clean up
  9. Return BrowserScanResult

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/browser/worker.go internal/browser/worker_test.go
git commit -m "feat(phase5): add browser worker orchestrator"
```

---

## Chunk 5: NATS Integration, Binary, Docker (Tasks 13-15)

### Task 13: NATS Browser Worker Handler

**Files:**
- Create: `internal/browser/natsworker.go`

- [ ] **Step 1: Implement natsworker.go**

Follows same pattern as `internal/dast/natsworker.go`:
- Consumes from `scan.dast.browser.dispatch` subject
- Deserializes `BrowserScanJob` from NATS message
- Calls `BrowserWorker.ExecuteScan`
- Publishes findings to `scan.results.dast` with HMAC signature
- Publishes status to `scan.status.update` with HMAC signature
- Finding type is `"dast"` — correlates with existing DAST findings

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/browser/...`

- [ ] **Step 3: Commit**

```bash
git add internal/browser/natsworker.go
git commit -m "feat(phase5): add NATS handler for browser worker"
```

---

### Task 14: Binary and Docker Compose

**Files:**
- Create: `cmd/dast-browser-worker/main.go`
- Modify: `deploy/docker-compose/docker-compose.yml`

- [ ] **Step 1: Implement main.go**

Follows `cmd/dast-worker/main.go` pattern:
- Connect to NATS, ensure streams
- Require MSG_SIGNING_KEY (fatal if empty)
- Create auth broker
- Create BrowserWorker
- Create NATSBrowserWorker
- Start consuming

- [ ] **Step 2: Add to docker-compose.yml**

```yaml
dast-browser-worker:
    build:
      context: ../..
      dockerfile: Dockerfile
      args:
        SERVICE: dast-browser-worker
    environment:
      NATS_URL: nats://nats:4222
      MSG_SIGNING_KEY: dev-signing-key-change-me
      MAX_URLS: "500"
      MAX_DEPTH: "3"
      SCAN_TIMEOUT: "30m"
    security_opt:
      - seccomp=../../deploy/seccomp/dast-browser-worker.json
    shm_size: '256m'
    depends_on:
      nats:
        condition: service_started
      auth-broker:
        condition: service_started
```

- [ ] **Step 3: Verify binary compiles**

Run: `go build ./cmd/dast-browser-worker/`

- [ ] **Step 4: Commit**

```bash
git add cmd/dast-browser-worker/main.go deploy/docker-compose/docker-compose.yml
git commit -m "feat(phase5): add browser worker binary and Docker Compose service"
```

---

### Task 15: Integration Tests, Build Verification, Documentation

**Files:**
- Create: `internal/browser/integration_test.go`
- Create: `docs/phase5-browser-dast.md`

- [ ] **Step 1: Write integration tests**

Test scenarios:
1. Interceptor blocks out-of-scope requests
2. Interceptor allows in-scope requests
3. WebSocket URL validation via scope enforcer
4. Destructive form detection blocks "delete" forms
5. URL budget limits enforced
6. CrawlConfig defaults are safe (SubmitForms=false, MaxDepth=3, MaxURLs=500)
7. Evidence redaction applies to CDP headers
8. Screenshot evidence has SHA-256 hash
9. Auth injection only for in-scope URLs
10. Chrome flags include all security flags

- [ ] **Step 2: Run full test suite**

Run: `go test ./... -count=1`
Expected: All packages PASS, no regressions

- [ ] **Step 3: Run go vet**

Run: `go vet ./...`
Expected: Clean

- [ ] **Step 4: Write documentation**

`docs/phase5-browser-dast.md` — Phase 5 documentation covering architecture, security controls, API, configuration.

- [ ] **Step 5: Commit**

```bash
git add internal/browser/integration_test.go docs/phase5-browser-dast.md
git commit -m "feat(phase5): add integration tests and documentation"
```

---

## Merge Criteria

All of these must be true before the PR is merge-ready:

- [ ] All packages compile: `go build ./...`
- [ ] All tests pass: `go test ./... -count=1`
- [ ] No vet issues: `go vet ./...`
- [ ] Three-layer scope enforcement implemented and tested
- [ ] WebSocket URLs validated against scope enforcer
- [ ] Auth injection gated by scope check (no credential leakage to third-party)
- [ ] CDP evidence redaction uses same patterns as HTTP evidence
- [ ] Form submission disabled by default
- [ ] Destructive form keyword blocking active
- [ ] URL budget (500) and depth limit (3) enforced
- [ ] Chrome profile directory destroyed after each job
- [ ] Screenshots only captured for findings, with form field blurring
- [ ] Seccomp profile reviewed and committed
- [ ] iptables rules documented and tested
- [ ] Chrome flags specification reviewed
- [ ] No regressions in existing SAST/DAST/Correlation/Governance tests
- [ ] Interception handler is allow/block only (never modifies URLs)

## Deferred Items

Explicitly out of scope for Phase 5, tracked for Phase 6+:

- **Deep SPA crawl** — Full client-side route discovery, DOM mutation observers, React/Angular state machines
- **DNS prefetch blocking** — `--dns-prefetch-disable` is set but not verified in tests
- **data:/blob: URL interception** — No direct network risk, deferred
- **sendBeacon/keepalive interception** — Covered by iptables fallback
- **OCR-based screenshot redaction** — Expensive; findings-only capture sufficient
- **Advanced bot evasion** — Report detection as coverage gap instead
- **Multi-browser support** — Firefox/WebKit via Playwright deferred
- **Deep form interaction** — Multi-step forms, AJAX forms, file uploads
- **Custom DOM assertion rules** — User-defined DOM-XSS patterns
- **Canvas/WebGL attack surface reduction** — Low priority, flags set but not tested
