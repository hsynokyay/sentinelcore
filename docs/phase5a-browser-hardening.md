# Phase 5a: Browser Worker Hardening and Security Redesign

**Status:** Design
**Date:** 2026-04-02
**Prerequisite for:** Phase 5 (Browser-Based DAST)
**Source of truth:** Phase 5 Security Review (31 issues, 17 merge blockers)

## 1. Purpose

This phase resolves all Critical and merge-blocking High issues from the Phase 5 security review before any browser crawling code is implemented. It establishes the security foundations — containment, scope safety, credential safety, and evidence privacy — that make browser-based DAST safe to build on.

No crawler features, DOM scanning, or form interaction logic is included. Those belong to Phase 5 proper and may only proceed after this phase is merged and reviewed.

---

## 2. Issues Fixed in This Phase

### Critical (all 7 resolved)

| ID | Issue | Resolution |
|----|-------|-----------|
| C1 | `execve` + `ptrace` removes containment | Dedicated seccomp profile; non-root user; read-only rootfs |
| C2 | `--no-sandbox` eliminates Chrome renderer isolation | Container-level compensation: user namespace remapping, seccomp-bpf, iptables |
| C3 | Third-party requests leak injected auth headers | Scope-gated credential injection: `Decide()` check BEFORE header injection |
| C4 | WebSocket bypass of `Fetch.requestPaused` | `ws`/`wss` scheme support in `pkg/scope/enforcer.go` + `Network.webSocketCreated` handler |
| C5 | CDP TOCTOU — DNS rebinding between scope check and connection | Three-layer enforcement: CDP (L1) + iptables (L2) + IP monitoring (L3) |
| C6 | Uncontrolled form submission triggers destructive actions | Not applicable to 5a (no forms yet). Safety model designed here, implemented in Phase 5 |
| C7 | Chrome renderer exploit + relaxed seccomp | Hardened container spec, Chrome version pinning, minimal capabilities |

### Merge-blocking High (all 10 resolved)

| ID | Issue | Resolution |
|----|-------|-----------|
| H1 | Chrome profile directory writable attack surface | Per-job tmpfs profile, destroyed after scan |
| H2 | CDP network events expose raw credentials in logs | CDP evidence redaction pipeline applying `SensitiveHeaders` + `SensitivePatterns` |
| H3 | Service Workers cache credentials | `--disable-features=ServiceWorker` Chrome flag |
| H4 | WebRTC ICE leaks container internal IPs | `--disable-features=WebRTC` Chrome flag |
| H5 | Web Worker requests bypass `Fetch.requestPaused` | iptables Layer 2 as fallback + `Fetch.enable` with wildcard patterns |
| H6 | Screenshots capture PII | Findings-only capture, form field blurring before screenshot |
| H7 | Credentials visible in form field screenshots | No screenshots during auth phase; input value replacement before capture |
| H8 | Compromised worker modifies requests via CDP | Interceptor is allow/block only — no URL/body modification methods exist |
| H9 | Infinite URL generation | URL budget (500), depth limit (3), wall-clock timeout (30m) |
| H10 | Browser memory leaks cause OOM | `--js-flags=--max-old-space-size=512`, container memory limits, Chrome restart on threshold |

### Deferred (not addressed in 5a)

| ID | Issue | Reason |
|----|-------|--------|
| M1 | DNS prefetch | Covered by iptables L2 and `--dns-prefetch-disable` flag |
| M2 | data:/blob: URLs | No direct network access |
| M3 | Remaining CDP TOCTOU | IP monitoring L3 + iptables L2 provides adequate coverage |
| M4 | Bot detection | Coverage concern, not security |
| M5 | DOM evidence deep sanitization | Body-level redaction sufficient for MVP |
| M6 | localStorage/IndexedDB | Per-job profile isolation eliminates cross-job risk |
| M9 | Request exfiltration via URL encoding | Defense-in-depth, not primary attack |

---

## 3. Updated Browser Worker Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                  CONTAINER BOUNDARY                           │
│  User: sentinel (non-root)                                    │
│  Rootfs: read-only (tmpfs: /tmp, /dev/shm)                  │
│  Capabilities: NET_RAW only (for iptables)                   │
│  Seccomp: dast-browser-worker.json                           │
│  iptables: browser-worker.sh (Layer 2)                       │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Go Process: dast-browser-worker                         │ │
│  │                                                          │ │
│  │  ┌──────────────┐  ┌────────────────────┐              │ │
│  │  │ NATS Handler  │  │ Browser Worker     │              │ │
│  │  │ (consume jobs)│→ │ (orchestrate scan) │              │ │
│  │  └──────────────┘  └────────┬───────────┘              │ │
│  │                              │                           │ │
│  │  ┌──────────────────────────┼────────────────────────┐  │ │
│  │  │              CDP Connection (loopback only)        │  │ │
│  │  │                          │                         │  │ │
│  │  │  ┌──────────────┐  ┌───┴────────┐  ┌──────────┐  │  │ │
│  │  │  │ Interceptor  │  │ Auth       │  │ Evidence  │  │  │ │
│  │  │  │ (L1: scope   │  │ Injector   │  │ Capture   │  │  │ │
│  │  │  │  allow/block)│  │ (scope-    │  │ (CDP-aware│  │  │ │
│  │  │  │              │  │  gated)    │  │  redact)  │  │  │ │
│  │  │  └──────────────┘  └────────────┘  └──────────┘  │  │ │
│  │  │                                                    │  │ │
│  │  │  ┌──────────────┐                                 │  │ │
│  │  │  │ Monitor (L3) │ ← Network.responseReceived      │  │ │
│  │  │  │ IP validation│   Network.webSocketCreated       │  │ │
│  │  │  └──────────────┘                                 │  │ │
│  │  └────────────────────────────────────────────────────┘  │ │
│  │                              │                           │ │
│  │  ┌──────────────────────────┴───────────────────────┐   │ │
│  │  │  Chrome (headless, --no-sandbox)                  │   │ │
│  │  │  PID namespace isolated, non-root                 │   │ │
│  │  │  Profile: /tmp/sentinel-chrome-<job-id> (tmpfs)   │   │ │
│  │  └──────────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  iptables (Layer 2): kernel-level network enforcement    │ │
│  │  DROP new→10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16   │ │
│  │  DROP new→127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10  │ │
│  │  ACCEPT loopback (lo interface), ESTABLISHED/RELATED     │ │
│  └─────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

**Key invariants:**
1. Chrome is always headless, always non-root, always with per-job profile on tmpfs
2. CDP connection is loopback-only (random port)
3. The Go process owns all network policy decisions — Chrome makes no unchecked requests
4. Three independent scope enforcement layers, none trusted alone

---

## 4. Container Hardening Specification

### 4.1 Base Image

```dockerfile
FROM chromedp/headless-shell:stable AS chrome
FROM golang:1.22-alpine AS builder
# ... build Go binary ...
FROM alpine:3.19
RUN adduser -D -u 1000 sentinel
COPY --from=chrome /headless-shell /headless-shell
COPY --from=builder /app/dast-browser-worker /usr/local/bin/
USER sentinel
ENTRYPOINT ["/usr/local/bin/dast-browser-worker"]
```

### 4.2 Runtime Configuration

| Property | Value | Rationale |
|----------|-------|-----------|
| User | `sentinel` (UID 1000, non-root) | Limits Chrome exploit impact |
| Rootfs | Read-only | Prevents persistent malware |
| tmpfs mounts | `/tmp` (512MB), `/dev/shm` (256MB) | Chrome profile + shared memory |
| Capabilities | `NET_RAW` only (for iptables init), dropped after setup | Minimal privilege |
| Seccomp | `dast-browser-worker.json` | Allows execve/fork for Chrome only |
| Memory limit | 2GB (container), 512MB (V8 heap) | OOM protection |
| PID limit | 256 | Prevents fork bombs |
| Network | Container network with iptables applied at startup | Layer 2 enforcement |

### 4.3 Chrome Launch Flags

| Flag | Security Property | Mitigates |
|------|------------------|-----------|
| `--headless=new` | No GUI attack surface | General |
| `--no-sandbox` | Relies on container isolation instead of Chrome sandbox | C2 (compensated by container controls) |
| `--disable-gpu` | Eliminates GPU process attack surface | M8 |
| `--disable-software-rasterizer` | No software rendering process | M8 |
| `--disable-dev-shm-usage` | Uses /tmp instead of /dev/shm | H11 |
| `--disable-background-networking` | No speculative connections | M1 |
| `--disable-features=ServiceWorker` | No credential caching in SW | H3 |
| `--disable-features=WebRTC` | No internal IP leak via ICE | H4 |
| `--disable-features=NetworkPrediction` | No speculative DNS/TCP | M1 |
| `--disable-features=AutofillServerCommunication` | No autofill network calls | L1 |
| `--disable-blink-features=AutomationControlled` | Removes webdriver flag | M4 |
| `--disable-component-update` | No background updates | General |
| `--disable-default-apps` | Minimal Chrome install | General |
| `--dns-prefetch-disable` | No speculative DNS | M1 |
| `--no-first-run` | Skip first-run wizards | General |
| `--js-flags=--max-old-space-size=512` | V8 heap limit | H10 |
| `--user-data-dir=/tmp/sentinel-chrome-<job-id>` | Per-job isolation | H1, H3 |

---

## 5. Three-Layer Scope Enforcement Design

### Layer 1: CDP Fetch.requestPaused (Application-Level)

**What it catches:** All HTTP/HTTPS requests from the main page, iframes, and most Web Workers.

**Mechanism:** `Fetch.enable` with `patterns: [{urlPattern: "*", requestStage: "Request"}]`. Every network request is paused before Chrome sends it. The interceptor calls `scope.Enforcer.CheckRequest(url)` and either allows (unmodified `Fetch.continueRequest`) or blocks (`Fetch.failRequest`).

**Limitation:** May not catch WebSocket connections, requests from some Web Worker contexts, or speculative connections. TOCTOU gap between scope check and Chrome's actual DNS resolution.

**Contract:** The interceptor is **allow/block only**. It has no method to modify request URLs, headers, or bodies. Auth header injection is the sole exception, performed inline only for allowed requests (since `Decide()` already proved scope).

### Layer 2: iptables/nftables (Kernel-Level)

**What it catches:** ALL outbound traffic from the container, regardless of source (Chrome, Web Workers, WebSocket, speculative, sendBeacon).

**Mechanism:** iptables rules applied at container startup via `deploy/iptables/browser-worker.sh`. Blocks NEW connections to all RFC 1918 ranges, loopback, link-local, cloud metadata, and reserved ranges. Allows loopback interface (for Chrome IPC) and ESTABLISHED/RELATED connections.

**Rule ordering:**
1. ACCEPT on `lo` interface (Chrome IPC)
2. DROP NEW connections to all blocked CIDRs
3. ACCEPT ESTABLISHED/RELATED (for legitimate scan traffic)
4. ACCEPT all else (external targets)

This ordering ensures that even if a DNS rebinding attack tricks Layer 1, the kernel blocks the actual connection to a private IP.

### Layer 3: Network.responseReceived IP Monitoring (Detection)

**What it catches:** Connections that bypassed Layer 1 and Layer 2 (should not happen, but defense-in-depth).

**Mechanism:** Listen to `Network.responseReceived` CDP events. Extract `remoteIPAddress` field. Validate against the scope enforcer's pinned IP set and blocked CIDRs. If a violation is detected: log alert, increment violation counter, abort scan if threshold exceeded.

Also listens to `Network.webSocketCreated` events and validates the WebSocket URL against the scope enforcer (with `ws`/`wss` → `http`/`https` scheme normalization).

---

## 6. Scope-Aware Auth Injection Design

### Problem

The existing `Session.ApplyTo(req)` in `internal/authbroker/strategy.go:39` injects all session headers and cookies unconditionally. In a browser context, this is unsafe because:
- Third-party resources loaded by the page would receive auth credentials
- Subresource requests to CDNs, analytics, etc. would leak tokens

### Solution

Auth credentials are injected **only in the CDP interceptor**, and **only for requests that passed scope enforcement**.

```
Request arrives at Fetch.requestPaused
    ↓
Interceptor.Decide(url) → Allow or Block
    ↓
If Block → Fetch.failRequest (no credentials ever touch the request)
If Allow → Inject auth headers inline, then Fetch.continueRequest
```

Since `Decide()` calls `scope.Enforcer.CheckRequest()`, any request that reaches the "inject" path is guaranteed to be in-scope. No redundant second check is needed.

### Cookie Injection

For `form_login` sessions that use cookies:
- Cookies are set via `Network.setCookie` at scan start
- Cookie attributes are hardened: `SameSite=Strict`, `HttpOnly=true`, `Secure=true`
- Cookie domain is validated: must match or be a subdomain of an allowed host
- Cookies for third-party domains in the session are rejected and logged

### Header Injection

For `bearer` and `oauth2_cc` sessions:
- Authorization headers are injected via `Fetch.continueRequest` with additional headers
- Only injected when `Decide()` returns `Allow`
- Never injected for cross-origin or third-party requests

---

## 7. WebSocket / Web Worker / Service Worker Handling

| Technology | Handling | Layer |
|-----------|----------|-------|
| WebSocket (`ws://`, `wss://`) | URL validated via `Network.webSocketCreated` event handler. Out-of-scope WebSockets logged and connection closed. `pkg/scope/enforcer.go` extended to accept `ws`/`wss` schemes. | L1 + L3 |
| Web Workers | Requests intercepted via `Fetch.requestPaused` (with wildcard pattern). Fallback: iptables blocks private IPs at kernel level. | L1 + L2 |
| Service Workers | Disabled entirely via `--disable-features=ServiceWorker`. Not needed for shallow crawl MVP. Re-evaluation in Phase 6 if SPA testing requires it. | Chrome flag |
| Shared Workers | Same as Web Workers — intercepted by Fetch + iptables fallback. | L1 + L2 |

---

## 8. CDP Evidence Redaction Design

### Problem

The existing evidence pipeline in `internal/dast/evidence.go` operates on Go `http.Request`/`http.Response` types. CDP network events are JSON structures with different field names and nesting.

### Solution

Export the redaction patterns from `internal/dast/evidence.go` (`SensitiveHeaders`, `SensitivePatterns`) and build a parallel CDP redaction layer in `internal/browser/evidence.go`.

**CDP Header Redaction:**
```
CDP event JSON → extract headers map → for each header:
    if lowercase(name) in SensitiveHeaders → replace value with "[REDACTED]"
→ redacted headers map
```

**CDP Body Redaction:**
```
Response body string → for each pattern in SensitivePatterns:
    regex.ReplaceAllString(body, "[REDACTED]")
→ redacted body string
```

**Screenshot Redaction:**
Before capturing any screenshot:
1. Inject CSS via `Runtime.evaluate`: `input, textarea { filter: blur(5px) }`
2. Replace input values: `el.value = '[REDACTED]'` for password and text fields
3. If blur injection fails (JS error), skip screenshot and log warning with `"blur_applied": "false"` metadata
4. Never capture screenshots during the authentication phase

**Evidence integrity:**
All evidence (network captures + screenshots) gets SHA-256 hash, consistent with existing `dast.Evidence.SHA256` field.

---

## 9. Screenshot Privacy / Redaction Model

| Rule | Rationale |
|------|-----------|
| Screenshots captured **only for confirmed findings** | Minimizes PII exposure surface |
| Never captured during authentication phase | Prevents credential screenshots |
| Form inputs blurred before capture | Prevents displaying user-entered data |
| Password fields replaced with `[REDACTED]` | Explicit credential removal |
| If blur fails, screenshot is skipped | Fail-safe: no unredacted screenshots |
| Screenshots stored with `metadata.type = "screenshot"` | Enables targeted retention policies |
| Screenshot evidence follows same SHA-256 integrity model | Consistency with HTTP evidence |

---

## 10. Form Submission Safety Model

**Default:** Read-only crawling. `CrawlConfig.SubmitForms = false`.

When form submission is explicitly enabled per scan job:

| Control | Mechanism |
|---------|-----------|
| Destructive keyword blocklist | Forms whose action URL, button text, or nearby labels contain: delete, remove, cancel, unsubscribe, pay, purchase, transfer, send, destroy, drop, terminate, revoke → NEVER submitted |
| Action URL scope validation | Form action must resolve to an allowed host |
| Method restriction | Only GET and POST allowed; PUT/DELETE/PATCH forms skipped |
| CSRF token preservation | If form has CSRF token field, include it in submission |
| Dry-run mode | Discover and log forms without submitting; default before full submission mode |

**Phase 5a scope:** The safety model is **designed** here but form submission is **not implemented** until Phase 5. Phase 5a only implements the `DestructiveKeywords` list and `IsDestructiveForm()` validation function.

---

## 11. Implementation Plan (Security Foundations Only)

### Milestone 1: Container and Seccomp (Week 1)
- `deploy/seccomp/dast-browser-worker.json` — relaxed seccomp profile
- `deploy/iptables/browser-worker.sh` — Layer 2 kernel-level enforcement
- `docs/browser-worker-chrome-flags.md` — reviewed artifact
- Container Dockerfile with non-root user, read-only rootfs, tmpfs mounts

### Milestone 2: Scope Enforcer Extensions (Week 1)
- `pkg/scope/enforcer.go` — add `ws`/`wss` scheme support to `CheckRequest`
- `internal/dast/evidence.go` — export `SensitiveHeaders` and `SensitivePatterns`
- Tests for WebSocket scheme handling

### Milestone 3: Chrome Lifecycle (Week 2)
- `internal/browser/types.go` — `BrowserScanJob`, `CrawlConfig`, `PageResult`, `FormInfo`
- `internal/browser/chrome.go` — Chrome launch with hardened flags, per-job profile, cleanup
- Tests: flag validation, profile isolation, cleanup verification

### Milestone 4: Three-Layer Scope Enforcement (Week 2-3)
- `internal/browser/interceptor.go` — CDP Fetch.requestPaused (Layer 1), allow/block only
- `internal/browser/monitor.go` — Network.responseReceived IP monitoring (Layer 3) + WebSocket handler
- Tests: in-scope allow, out-of-scope block, private IP block, WebSocket block, violation counting

### Milestone 5: Auth and Evidence (Week 3)
- `internal/browser/auth.go` — scope-gated cookie/header injection, cookie domain validation
- `internal/browser/evidence.go` — CDP header/body redaction, screenshot capture with blur
- Tests: auth injection scope-gating, redaction pattern coverage, screenshot blur failure handling

### Milestone 6: Worker Shell and Binary (Week 4)
- `internal/browser/worker.go` — worker orchestrator (setup layers, run scan, cleanup)
- `internal/browser/natsworker.go` — NATS consumer for `scan.dast.browser.dispatch`
- `cmd/dast-browser-worker/main.go` — binary entry point
- Docker Compose service entry
- Full build and test verification

### What is NOT in Phase 5a
- Crawler logic (link/form discovery, depth traversal)
- DOM security scanner (XSS, redirect, mixed content detection)
- Test case generation for browser-specific vulnerabilities
- Form interaction or submission
- SPA route discovery

---

## 12. Risks

| Risk | Mitigation |
|------|-----------|
| Chrome version has known CVEs | Pin to latest stable, document update cadence |
| iptables rules not applied (container startup race) | Worker refuses to start scan until iptables verification completes |
| CDP connection hijacked | Random port, loopback only, no external listening |
| Memory exhaustion from Chrome | Container memory limit (2GB), V8 heap limit (512MB), process kill on OOM |
| Seccomp profile too permissive | Reviewed artifact with explicit justification for every allowed syscall above the DAST baseline |
