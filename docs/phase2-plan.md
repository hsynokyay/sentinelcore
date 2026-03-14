# SentinelCore Phase 2 — API-First DAST & Orchestration Expansion

**Version:** 0.1.0
**Date:** 2026-03-14
**Status:** IMPLEMENTATION

---

## 1. Objectives

Phase 2 transforms SentinelCore from a SAST-only platform into a full SAST+DAST security scanner. Key goals:

1. **API-first DAST** — HTTP/REST/JSON testing driven by OpenAPI specs before browser crawling
2. **Auth Session Broker** — centralized credential management for authenticated scanning
3. **Runtime scope enforcement** — multi-layer protection preventing DAST scope escape
4. **Evidence capture** — full HTTP request/response evidence with credential redaction
5. **Orchestration hardening** — DNS pinning, NetworkPolicy lifecycle, checkpoint resume

## 2. API-First Rationale

Browser-based DAST is expensive and fragile. API-first approach:
- Drives tests from OpenAPI/Swagger specs — deterministic, reproducible
- Tests every endpoint systematically (not just what a crawler finds)
- Runs 10-50x faster than browser crawling
- Produces structured evidence (HTTP req/res pairs)
- Browser crawling added in Phase 3 as a complement, not replacement

## 3. New Components

| Component | Location | Purpose |
|---|---|---|
| Scope Enforcement Library | `pkg/scope/` | IP blocklist, DNS rebinding detection, redirect validation |
| Auth Session Broker | `cmd/auth-broker/`, `internal/authbroker/` | Manage authenticated sessions for DAST scans |
| DAST Worker | `cmd/dast-worker/`, `internal/dast/` | API-first HTTP scanner |
| Request Scheduler | `internal/dast/scheduler.go` | Rate-limited, scope-checked request dispatch |
| NetworkPolicy Controller | `internal/orchestrator/npcontroller.go` | Dynamic K8s NetworkPolicy for DAST scans |

## 4. Scope Enforcement Design

Six-layer enforcement pipeline:

1. **Target verification** — DNS TXT or HTTP well-known proof of ownership
2. **Policy evaluation** — OPA policy check before scan start
3. **DNS pinning** — resolve target IPs at scan start, pin for duration
4. **Kubernetes NetworkPolicy** — restrict worker egress to pinned IPs only
5. **Application-level checks** — every HTTP request validated against scope
6. **Monitoring** — `sentinelcore_scope_violation_total` metric, auto-abort on violation

### IP Blocklist (RFC 1918 + link-local + loopback + metadata)

```
10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
::1/128, fc00::/7, fe80::/10, 169.254.0.0/16,
100.64.0.0/10, 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15,
198.51.100.0/24, 203.0.113.0/24, 0.0.0.0/8, 240.0.0.0/4
```

### DNS Rebinding Prevention

- Resolve all target hostnames at scan start → pin IP set
- On every HTTP request: re-resolve, compare against pinned set
- If new IP not in pinned set → block request, increment violation counter
- If violation count > threshold → abort scan

## 5. Auth Session Broker Design

### Auth Strategies

| Strategy | Use Case |
|---|---|
| `bearer` | Static API token/key in Authorization header |
| `oauth2_cc` | OAuth2 Client Credentials flow |
| `form_login` | HTML form-based login with session cookie |
| `api_key` | API key in header, query param, or cookie |
| `scripted` | Multi-step custom auth sequence |

### Interface

```go
type AuthStrategy interface {
    Name() string
    Authenticate(ctx context.Context, config AuthConfig) (*Session, error)
    Refresh(ctx context.Context, session *Session) (*Session, error)
    Validate(ctx context.Context, session *Session) (bool, error)
}

type Session struct {
    ID          string
    ScanJobID   string
    Headers     map[string]string  // injected into every request
    Cookies     []*http.Cookie
    ExpiresAt   time.Time
    RefreshFunc string             // strategy name for refresh
}
```

### Credential Storage

- Credentials fetched from Vault per-request, never cached beyond session lifetime
- Session tokens stored in-memory only (never persisted to disk/DB)
- All credentials redacted from evidence capture
- Session auto-expires after scan completion or configurable timeout

## 6. DAST Worker Design

### Request Flow

```
OpenAPI Spec → Parser → Test Case Generator → Request Scheduler → HTTP Client → Evidence Capture
                                                    ↓
                                            Scope Enforcer (per-request)
                                                    ↓
                                            Auth Session (header injection)
```

### Test Case Generation

From OpenAPI spec, generate test cases for:
- SQL injection (parameterized payloads per input type)
- XSS (reflected, stored detection)
- Path traversal
- SSRF (internal IP detection)
- Authentication bypass
- IDOR (ID manipulation)
- Header injection
- Open redirect

### Evidence Capture

Every finding includes:
- Full HTTP request (method, URL, headers, body) — credentials redacted
- Full HTTP response (status, headers, body truncated at 1MB)
- SHA-256 hash of evidence bundle
- Timing information
- Scanner metadata (rule ID, confidence, severity)

## 7. Orchestration Improvements

### DNS Pinning
- Orchestrator resolves target DNS before dispatching to worker
- Pinned IPs passed to worker via scan job metadata
- Worker validates against pinned set on every request

### NetworkPolicy Lifecycle
- Create: on scan job start, restrict worker pod egress to pinned IPs + control plane
- Delete: on scan job completion/failure/timeout
- GC CronJob: every 5 min, clean up orphaned policies (TTL-based)

### Checkpoint Resume
- Worker periodically saves progress (completed endpoints, current position)
- On crash/restart, resume from last checkpoint
- Stored in `scans.scan_checkpoints` table

## 8. Worker Isolation

DAST worker seccomp profile allows network syscalls (unlike SAST):
- `socket`, `connect`, `bind`, `listen`, `accept`, `sendto`, `recvfrom`
- `read`, `write`, `close`, `mmap`, `munmap`, `brk`
- Blocks: `execve`, `fork`, `clone`, `ptrace`, `mount`, filesystem writes

Worker pods run:
- Non-root (UID 65534)
- Read-only root filesystem
- No host mounts
- Resource limits (CPU, memory, ephemeral storage)
- Network restricted by dynamic NetworkPolicy

## 9. Data Model Changes

### New Tables

```sql
-- Auth session tracking
CREATE TABLE auth.auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL REFERENCES scans.scan_jobs(id),
    strategy VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    refreshed_at TIMESTAMPTZ,
    metadata JSONB
);

-- Scan progress checkpoints
CREATE TABLE scans.scan_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL REFERENCES scans.scan_jobs(id),
    worker_id VARCHAR(255) NOT NULL,
    checkpoint_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(scan_job_id, worker_id)
);

-- Worker registration for result signing
CREATE TABLE scans.worker_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_id VARCHAR(255) NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT now(),
    worker_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
);
```

### Schema Changes

- `scans.scan_jobs`: add `scope_document JSONB`, `pinned_ips TEXT[]`, `scan_type VARCHAR(20) DEFAULT 'sast'`
- `scans.scan_targets`: add `openapi_spec_ref TEXT`, `auth_config_id UUID`

## 10. Test Strategy

- **Unit tests**: every public function, table-driven
- **Scope enforcement tests**: 20+ adversarial cases (SSRF, rebinding, redirect chains)
- **Auth broker tests**: all 5 strategies with mock servers
- **Integration tests**: full scan flow with test HTTP server
- **Evidence tests**: redaction verification, hash integrity

## 11. Milestones

| Week | Deliverable |
|---|---|
| 1 | `pkg/scope` — scope enforcement library with tests |
| 2 | `internal/authbroker` — auth strategies and session management |
| 3-4 | `internal/dast` — worker, scheduler, test case generator |
| 5 | Evidence capture and credential redaction |
| 6 | Orchestration: DNS pinning, NetworkPolicy controller |
| 7 | Checkpoint resume, worker registration |
| 8 | Integration tests, adversarial scope tests |
| 9 | Seccomp profiles, docs, migration scripts |
| 10 | End-to-end validation, PR |

## 12. Risks & Open Questions

| Risk | Mitigation |
|---|---|
| OpenAPI spec parsing edge cases | Use well-tested library (kin-openapi); fall back to endpoint list |
| Auth token expiry mid-scan | Proactive refresh with configurable buffer (default 60s before expiry) |
| DNS TTL vs scan duration mismatch | Re-resolve periodically, compare against pinned set |
| Large API surfaces (1000+ endpoints) | Configurable concurrency limits, checkpoint resume |
| False positives from WAF/rate limiting | Adaptive rate limiting, WAF detection heuristics |
