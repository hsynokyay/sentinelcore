# Phase 8 — Platform Security & Hardening

**Date**: 2026-04-19
**Branch**: `deploy/phase8-platform-hardening` (to be created)
**Prereqs**: Phase 7 data security complete (tenancy + secrets + role split)
**Owner**: Security officer + platform eng

---

## 1. Goal

Make SentinelCore operationally and defensively strong enough for
enterprise and financial customers. Shift from "works securely" to
"provably secure by default": every process runs with the least
privilege it needs; every request goes through a chain of validated
controls; every dependency is known, scanned, and signed.

Out of scope: cryptographic protocol changes (Phase 7 already shipped
envelope encryption + HMAC chain + pepper); feature-level AuthZ
(RBAC already exists).

---

## 2. Current state (survey, 2026-04-19)

**Already in place:**

- Rate limiting (`pkg/ratelimit`) — per-IP token bucket middleware.
- CSRF protection (`pkg/csrf`) — double-submit cookie pattern.
- CORS (`pkg/cors`) — allowlist middleware.
- JWT session auth with Redis-backed revocation (`pkg/auth`,
  `internal/apikeys`).
- Cookies: `HttpOnly` + `Secure` + `SameSite=Lax` on most paths;
  `SameSite=Strict` in the browser worker.
- RBAC capability checks at route wrappers (`policy.Evaluate`).
- Seccomp profiles for DAST/SAST workers
  (`deploy/seccomp/{dast-worker,dast-browser-worker,sast-worker}.json`).
- `read_only: true` + `tmpfs` on a subset of worker containers.
- Phase 7 split DB roles + BYPASSRLS on audit-writer + worker.
- Phase 7 envelope encryption + HMAC pepper for API keys.

**Gaps:**

- No idle-timeout or absolute-session-lifetime enforcement.
- No session rotation on privilege change.
- Controlplane + audit-service containers run as default user, no
  seccomp profile, no read-only root, no capability drop.
- No GitHub Actions pipeline — dependency scan, image scan, SBOM,
  signing all absent from CI.
- No pinned base images; `alpine:3.19` + `golang:1.26-alpine` pulled
  by tag, not digest.
- No webhook signature verification on inbound webhooks (outbound
  signs via HMAC, inbound is open).
- Export endpoints return HTML via `text/markdown`; no explicit
  `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`
  enforcement.
- No request size cap at the HTTP layer — `decodeJSON` accepts
  arbitrary body size.
- Error responses sometimes leak stack traces in debug mode; no
  audit to confirm debug mode is off in prod.
- Admin endpoints (owner-only routes) lack step-up auth — a stolen
  session can immediately drop users, rotate keys, etc.

---

## 3. Hardening Model

Five concentric layers. Each layer's failure is covered by the next.

```
  ┌────────────────────────────────────────────────────────────┐
  │ Layer 5 — Supply-chain trust (CI gates, signing, SBOM)     │
  │  ┌──────────────────────────────────────────────────────┐  │
  │  │ Layer 4 — Runtime sandbox (seccomp, caps, RO fs)     │  │
  │  │  ┌────────────────────────────────────────────────┐  │  │
  │  │  │ Layer 3 — Container/network boundary           │  │  │
  │  │  │  ┌──────────────────────────────────────────┐  │  │  │
  │  │  │  │ Layer 2 — Session & request security     │  │  │  │
  │  │  │  │  ┌────────────────────────────────────┐  │  │  │  │
  │  │  │  │  │ Layer 1 — Application controls     │  │  │  │  │
  │  │  │  │  │ (input val, rate limit, authz)     │  │  │  │  │
  │  │  │  │  └────────────────────────────────────┘  │  │  │  │
  │  │  │  └──────────────────────────────────────────┘  │  │  │
  │  │  └────────────────────────────────────────────────┘  │  │
  │  └──────────────────────────────────────────────────────┘  │
  └────────────────────────────────────────────────────────────┘
```

Design rule: an attacker who breaks N must still be stopped by N+1.
An attacker who gets past all five has already compromised the
build farm, the operator, and the runtime — the system is off the
table.

---

## 4. Security control catalog

Each control has: **ID**, where enforced, priority (P1 = ship first,
P2 = ship alongside, P3 = ship after), and an invariant line.

### 4.1 Layer 1 — Application controls

| ID | Control | Enforced at | Priority |
|---|---|---|---|
| A1 | Request size cap (1 MB default, 10 MB for file uploads) | `internal/controlplane/server.go` middleware | P1 |
| A2 | Per-endpoint rate limit (login: 5/min, write: 60/min, read: 300/min) | `pkg/ratelimit` registered per route | P1 |
| A3 | JSON schema validation on every POST/PATCH body | generated from request struct tags | P2 |
| A4 | HTML/SSRF-safe URL parsing for user-supplied URLs | `pkg/netutil.ParseSafeURL` (new) | P1 |
| A5 | Webhook-in signature verification (X-Signature header) | `internal/controlplane/api/webhooks_inbound.go` | P2 |
| A6 | Export endpoints: always `Content-Disposition: attachment` + `nosniff` + `X-Frame-Options: DENY` | export handlers | P1 |
| A7 | Admin endpoint step-up: require recent re-auth (<5 min) for destructive ops | `RequireStepUp` middleware | P1 |
| A8 | No debug mode in prod (gated on SC_ENV=production) | build-time + startup assertion | P1 |
| A9 | Uniform error bodies (no stack traces to clients) | `writeError` central path | P1 |
| A10 | Audit-log every admin mutation (already done in Phase 6) | `emitAuditEvent` | — (done) |
| A11 | File upload content-type sniff + extension whitelist | upload handlers | P2 |
| A12 | PDF/Markdown/SARIF export — sanitize user content before template render | `pkg/export` sanitizer | P1 |

**Invariant**: every HTTP handler passes through A1, A2, A9 before
any tenant DB access.

### 4.2 Layer 2 — Session & request security

| ID | Control | Enforced at | Priority |
|---|---|---|---|
| S1 | Cookie: `Secure`, `HttpOnly`, `SameSite=Lax` (Strict on /admin/*) | cookie helper | P1 |
| S2 | Idle timeout: 30 min of inactivity → force reauth | Redis session TTL + sliding | P1 |
| S3 | Absolute lifetime: 12 h from login → force reauth | JWT `exp` + DB check | P1 |
| S4 | Session rotation on privilege change | auth handler, role update | P1 |
| S5 | Logout revokes both access JWT + refresh + Redis session | `/auth/logout` | P1 |
| S6 | CSRF: double-submit cookie on state-changing requests | `pkg/csrf` middleware | — (exists) |
| S7 | Rate-limit login per email (10/hr) AND per IP (60/hr) | per-key limiter | P1 |
| S8 | Suspicious session event emission (geo-jump, UA change, concurrent session ceiling) | auth middleware | P2 |
| S9 | Step-up reauth for admin mutations (A7 at application level) | see A7 | P1 |
| S10 | Refresh-token rotation (each use generates new refresh) | refresh handler | P2 |

**Invariant**: a stolen access token's blast radius ≤ 30 min (S2) and
cannot extend past 12 h (S3); a stolen refresh token rotates on each
use (S10) so observable replay is possible.

### 4.3 Layer 3 — Container / network

| ID | Control | Enforced at | Priority |
|---|---|---|---|
| C1 | All service containers: `user: "1000:1000"` (non-root) | docker-compose.yml | P1 |
| C2 | All service containers: `read_only: true` + explicit tmpfs | docker-compose.yml | P1 |
| C3 | `cap_drop: [ALL]` + minimal `cap_add` (none for controlplane) | docker-compose.yml | P1 |
| C4 | `no-new-privileges:true` security_opt | docker-compose.yml | P1 |
| C5 | Dedicated seccomp profile per service (default-deny, allowlist syscalls) | deploy/seccomp/*.json | P2 |
| C6 | Network segmentation: three Docker networks (proxy, data, internal) — only nginx in proxy | docker-compose.yml | P1 |
| C7 | No published ports except nginx 443/80 | host firewall + compose | P1 |
| C8 | Health endpoints bound to localhost inside container (nginx exposes `/healthz` on LB side) | controlplane config | P2 |
| C9 | Postgres + Redis + NATS: listen on `127.0.0.1` or Docker network only, NEVER 0.0.0.0 on host | compose.yml ports stanza | P1 |
| C10 | Reverse-proxy-only termination: HSTS, TLS 1.3, OCSP stapling | nginx.conf | P1 |

**Invariant**: `nmap 77.42.34.174` from the outside shows only 22
(SSH) + 80 (HTTP→443 redirect) + 443. Everything else is internal.

### 4.4 Layer 4 — Runtime sandbox

| ID | Control | Enforced at | Priority |
|---|---|---|---|
| R1 | Base images: distroless or alpine pinned by digest (`@sha256:...`) | Dockerfile | P1 |
| R2 | Multi-stage build: final image contains only the static Go binary + ca-certs | Dockerfile | — (done) |
| R3 | No shell in final image (distroless variant) | Dockerfile | P2 |
| R4 | Memory limit per container (500 MB controlplane, 200 MB workers) | docker-compose.yml | P1 |
| R5 | PID limit (100 for controlplane, 50 for workers) | docker-compose.yml | P2 |
| R6 | Log driver: json-file with rotation (max-size=100m, max-file=3) | docker-compose.yml | P1 |
| R7 | `security_opt: apparmor=...` (docker default or custom profile) | docker-compose.yml | P3 |

**Invariant**: a compromised worker cannot fork-bomb, cannot write
outside `/tmp` (tmpfs), cannot call syscalls outside its seccomp
allowlist.

### 4.5 Layer 5 — Supply chain

| ID | Control | Enforced at | Priority |
|---|---|---|---|
| X1 | `govulncheck` against every PR, fail on critical/high matched to called code | `.github/workflows/ci.yml` | P1 |
| X2 | `go mod verify` + `go mod tidy` enforced clean (diff check) | CI | P1 |
| X3 | `trivy image` scan of every built image, fail on high+ critical | CI (release workflow) | P1 |
| X4 | SBOM (CycloneDX JSON) generated per image via `syft` | CI artifacts | P1 |
| X5 | Image signing with `cosign` using keyless OIDC (GitHub Actions identity) | release workflow | P2 |
| X6 | Frontend npm: `npm audit --audit-level=high --production` fails build | CI | P1 |
| X7 | License allow-list check (no AGPL, no unknown) | CI | P2 |
| X8 | Dependency version pinning: go.sum required, package-lock.json required | CI | — (mostly done) |
| X9 | Dependabot / Renovate: weekly PRs, auto-merge patch-level after CI green | `.github/dependabot.yml` | P2 |

**Invariant**: a release artifact's provenance can be traced to:
commit SHA → CI run → scanner results → signed image.

---

## 5. Session / request security — concrete defaults

### 5.1 Cookie policy

```go
// pkg/auth/cookies.go — single helper that every handler MUST use.
func SetSessionCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
    http.SetCookie(w, &http.Cookie{
        Name:     name,
        Value:    value,
        Path:     "/",
        MaxAge:   int(maxAge.Seconds()),
        HttpOnly: true,
        Secure:   true,        // never false in prod; dev uses a build tag
        SameSite: http.SameSiteLaxMode,  // Strict on /admin routes via separate helper
    })
}
```

### 5.2 Session lifetimes

| Token | TTL | Behaviour |
|---|---|---|
| Access JWT | 15 min | Every request refreshes sliding idle counter in Redis |
| Refresh token | 7 d (idle) / 30 d (absolute) | Rotates on every use; old token invalidated |
| Idle timeout | 30 min | Redis `EXPIRE sess:{jti} 1800` on every request |
| Absolute lifetime | 12 h | JWT `exp` + server-side check against session creation timestamp |
| Step-up reauth | 5 min window | Destructive admin ops require `last_reauth_at < 5m` |

### 5.3 Middleware flow

```
request → TLS termination (nginx) → CORS → Rate limit →
   Request size cap → CSRF → Auth (JWT/API key) →
   Session idle+absolute check → Step-up check (admin routes) →
   RBAC capability check → Tenant scope (Phase 7) →
   Handler → Response
```

Each layer is a `http.Handler` wrapper. Order matters: rate limit
BEFORE auth so credential-stuffing is rate-limited on the IP axis
before Redis sees the request.

### 5.4 Schema changes

```sql
-- 041_session_hardening.up.sql
ALTER TABLE auth.auth_sessions
    ADD COLUMN IF NOT EXISTS created_at_absolute TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_reauth_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ip_fingerprint      TEXT,  -- hash of (asn, /24) — not raw IP
    ADD COLUMN IF NOT EXISTS ua_fingerprint      TEXT;  -- hash of parsed UA major

-- When ip_fingerprint / ua_fingerprint change mid-session,
-- emit auth.session.suspicious event + force reauth.
```

---

## 6. Deployment hardening — concrete config

### 6.1 docker-compose.yml diff (controlplane example)

```yaml
controlplane:
  image: sentinelcore/controlplane@sha256:<digest>  # pinned by digest
  user: "1000:1000"
  read_only: true
  tmpfs:
    - /tmp:size=64m,mode=1777
  cap_drop:
    - ALL
  security_opt:
    - no-new-privileges:true
    - seccomp=/opt/sentinelcore/seccomp/controlplane.json
  deploy:
    resources:
      limits:
        memory: 500m
        pids: 100
  logging:
    driver: json-file
    options:
      max-size: "100m"
      max-file: "3"
  networks:
    - data        # can talk to postgres, redis, nats
    - proxy       # nginx reverses to this
  # NO `ports:` — only nginx has ports
```

### 6.2 Network segmentation

```yaml
networks:
  proxy:      # nginx <-> controlplane
    driver: bridge
    internal: false
  data:       # controlplane/workers <-> postgres/redis/nats
    driver: bridge
    internal: true   # no egress to internet
  internal:   # worker-to-worker (NATS bus)
    driver: bridge
    internal: true
```

### 6.3 Seccomp profile skeleton

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read","write","open","openat","close","stat","fstat","lstat",
        "mmap","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn",
        "ioctl","pread64","pwrite64","readv","writev","access","pipe",
        "select","sched_yield","mremap","msync","mincore","madvise",
        "shmget","shmat","shmctl","dup","dup2","nanosleep","getitimer",
        "alarm","setitimer","getpid","sendfile","socket","connect",
        "accept","sendto","recvfrom","sendmsg","recvmsg","shutdown",
        "bind","listen","getsockname","getpeername","socketpair",
        "setsockopt","getsockopt","clone","fork","vfork","execve",
        "exit","wait4","kill","uname","fcntl","flock","fsync","getcwd",
        "chdir","mkdir","rmdir","creat","unlink","readlink","umask",
        "gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace",
        "getuid","syslog","getgid","setuid","setgid","geteuid","getegid",
        "setpgid","getppid","getpgrp","setsid","setreuid","setregid",
        "getgroups","setgroups","setresuid","getresuid","setresgid",
        "getresgid","getpgid","capget","capset","rt_sigpending",
        "rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack",
        "utime","mknod","personality","ustat","statfs","fstatfs","getpriority",
        "setpriority","sched_setparam","sched_getparam","sched_setscheduler",
        "sched_getscheduler","sched_get_priority_max","sched_get_priority_min",
        "sched_rr_get_interval","mlock","munlock","mlockall","munlockall",
        "vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl",
        "adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount",
        "umount2","swapon","swapoff","reboot","sethostname","setdomainname",
        "iopl","ioperm","gettid","readahead","setxattr","lsetxattr","fsetxattr",
        "getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr",
        "removexattr","lremovexattr","fremovexattr","tkill","time","futex",
        "sched_setaffinity","sched_getaffinity","set_thread_area","io_setup",
        "io_destroy","io_getevents","io_submit","io_cancel","get_thread_area",
        "lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old",
        "remap_file_pages","getdents64","set_tid_address","restart_syscall",
        "semtimedop","fadvise64","timer_create","timer_settime","timer_gettime",
        "timer_getoverrun","timer_delete","clock_settime","clock_gettime",
        "clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl",
        "tgkill","utimes","mbind","set_mempolicy","get_mempolicy","mq_open",
        "mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr",
        "kexec_load","waitid","add_key","request_key","keyctl","ioprio_set",
        "ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch",
        "migrate_pages","openat","mkdirat","mknodat","fchownat","futimesat",
        "newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat",
        "fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list",
        "get_robust_list","splice","tee","sync_file_range","vmsplice",
        "move_pages","utimensat","epoll_pwait","signalfd","timerfd_create",
        "eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4",
        "signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1",
        "preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg",
        "fanotify_init","fanotify_mark","prlimit64","name_to_handle_at",
        "open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns",
        "getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module",
        "sched_setattr","sched_getattr","renameat2","seccomp","getrandom",
        "memfd_create","bpf","execveat","userfaultfd","membarrier","mlock2",
        "copy_file_range","preadv2","pwritev2","statx","rseq"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

(That's ~180 syscalls — the Docker default profile. We'll start here
and tighten by removing unused calls after a 2-week observation
window with `auditd`.)

---

## 7. Supply-chain plan

### 7.1 CI pipeline (`.github/workflows/ci.yml`)

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]

jobs:
  go:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26' }
      - run: go mod verify
      - run: go build ./...
      - run: go test -race ./...
      - run: go vet ./...
      - name: govulncheck
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...                 # exits non-zero on match
      - name: staticcheck
        run: |
          go install honnef.co/go/tools/cmd/staticcheck@latest
          staticcheck ./...

  npm:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '22' }
      - run: cd web && npm ci
      - run: cd web && npm audit --audit-level=high --production
      - run: cd web && npm run build
      - run: cd web && npm test

  container-scan:
    runs-on: ubuntu-24.04
    needs: [go, npm]
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4
      - name: build controlplane image
        run: docker build --build-arg SERVICE=controlplane -t sc:pr-${{ github.sha }} .
      - name: trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: sc:pr-${{ github.sha }}
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
      - name: generate SBOM
        run: |
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            anchore/syft:latest sc:pr-${{ github.sha }} -o cyclonedx-json > sbom.json
      - uses: actions/upload-artifact@v4
        with: { name: sbom, path: sbom.json }
```

### 7.2 Release pipeline (`.github/workflows/release.yml`)

```yaml
name: release
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  id-token: write  # for cosign keyless

jobs:
  build-and-sign:
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        service:
          - controlplane
          - audit-service
          - sast-worker
          - dast-worker
          - notification-worker
          - retention-worker
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: build and push
        run: |
          docker buildx build \
            --build-arg SERVICE=${{ matrix.service }} \
            -t ghcr.io/sentinelcore/${{ matrix.service }}:${{ github.ref_name }} \
            --push .
      - name: cosign sign
        run: |
          cosign sign --yes ghcr.io/sentinelcore/${{ matrix.service }}:${{ github.ref_name }}
      - name: generate + attach SBOM
        run: |
          syft ghcr.io/sentinelcore/${{ matrix.service }}:${{ github.ref_name }} \
            -o cyclonedx-json=${{ matrix.service }}.sbom.json
          cosign attach sbom \
            --sbom ${{ matrix.service }}.sbom.json \
            ghcr.io/sentinelcore/${{ matrix.service }}:${{ github.ref_name }}
```

### 7.3 Dependabot (`.github/dependabot.yml`)

```yaml
version: 2
updates:
  - package-ecosystem: gomod
    directory: "/"
    schedule: { interval: weekly, day: monday }
    open-pull-requests-limit: 5
    commit-message:
      prefix: "chore(deps)"
  - package-ecosystem: npm
    directory: "/web"
    schedule: { interval: weekly, day: monday }
    commit-message:
      prefix: "chore(deps-frontend)"
  - package-ecosystem: docker
    directory: "/"
    schedule: { interval: weekly, day: monday }
  - package-ecosystem: github-actions
    directory: "/"
    schedule: { interval: weekly, day: monday }
```

### 7.4 Release artifact trust model

```
Customer receives:
  1. OCI image (ghcr.io/sentinelcore/<service>:<tag>)
  2. Signature (cosign, attached to image)
  3. SBOM (cyclonedx-json, attached to image)

Customer verifies:
  $ cosign verify \
       --certificate-identity-regexp '^https://github\.com/.../' \
       --certificate-oidc-issuer https://token.actions.githubusercontent.com \
       ghcr.io/sentinelcore/controlplane:v1.2.3

  $ cosign download sbom ghcr.io/sentinelcore/controlplane:v1.2.3 \
       | jq '.components[] | select(.licenses[]?.license.id == "AGPL-3.0")'
  # empty = OK

Customer admission controller (optional):
  - Kyverno or cosign admission webhook that rejects unsigned
    or unverified images in the cluster.
```

---

## 8. Implementation plan

30-day rollout, three waves. Each wave independently revertable.

### Wave 1 — Application + session hardening (week 1–2)

**Goal**: tighten the HTTP layer without touching deployment.

Files:

```
pkg/httpsec/
  middleware.go          # Chained: RequestSizeCap, NoSniff, HSTS, StepUp
  middleware_test.go
  cookies.go             # SetSessionCookie / SetStrictCookie single helpers
  stepup.go              # RequireStepUp middleware + last_reauth_at tracking
internal/controlplane/server.go   # register new middleware chain
internal/controlplane/api/webhooks_inbound.go  # signature verification
pkg/netutil/
  safe_url.go            # SSRF-safe URL parser (reject private IP ranges)
  safe_url_test.go
migrations/
  041_session_hardening.up.sql / .down.sql
docs/
  session-security.md    # operator-facing doc: idle / absolute / step-up
```

Changes:

1. Add `pkg/httpsec` package. Export `Chain(h http.Handler, opts ...Option) http.Handler`.
2. Wire into `server.go` as the OUTERMOST wrapper (before router).
3. Migration 041 adds the three session columns.
4. Update auth handlers to maintain `last_reauth_at` on password login + re-enter-password flow.
5. Add `RequireStepUp` middleware on destructive admin routes:
   - `DELETE /users/{id}`, `POST /apikeys/rotate`, `POST /organizations/*/delete`, etc.
6. Implement webhook-inbound signature verifier (HMAC-SHA256, replay protection via `X-Timestamp` ±5 min).

Revert path: remove middleware registration; migrations 041 down.

### Wave 2 — Deployment hardening (week 2–3)

**Goal**: harden every container and the network posture.

Files:

```
deploy/docker-compose/docker-compose.yml        # full rewrite of security fields
deploy/seccomp/controlplane.json                # new
deploy/seccomp/audit-service.json               # new
deploy/seccomp/notification-worker.json         # new
deploy/seccomp/retention-worker.json            # new
deploy/nginx.conf                               # HSTS, TLS 1.3, OCSP
Dockerfile                                      # pin base images by digest
Dockerfile.distroless                           # variant for controlplane
docs/deployment-hardening.md                    # operator runbook addendum
```

Changes:

1. Pin `golang:1.26-alpine` and `alpine:3.19` by digest.
2. Create seccomp profiles for every service (start from Docker default, then tighten).
3. Rewrite compose for every service with C1–C10 controls from §4.3.
4. Add network segmentation (three networks).
5. Add resource limits (memory, pids).
6. Nginx: HSTS max-age=31536000 + includeSubDomains, TLS 1.3 only, strict CSP.
7. Verify no service binds 0.0.0.0 on the host.

Revert path: compose rollback (previous compose.yml kept as `.bak`).

### Wave 3 — Supply chain (week 3–4)

**Goal**: every released image is scanned, signed, and has an SBOM.

Files:

```
.github/workflows/ci.yml                        # new
.github/workflows/release.yml                   # new
.github/workflows/dependabot.yml                # actions/dependabot upgrades
.github/dependabot.yml                          # new
docs/release-security.md                        # trust model for customers
scripts/verify-release.sh                       # customer-facing verify script
```

Changes:

1. Create CI workflow with govulncheck + staticcheck + trivy + syft.
2. Create release workflow with buildx + cosign keyless + sbom attach.
3. Enable Dependabot on gomod, npm, docker, actions.
4. Document customer verification in `docs/release-security.md`.
5. Run one dry-run release to sanity-check the pipeline.

Revert path: disable the workflows (keep files for rollback testing).

---

## 9. Verification checklist

Each item has a pass/fail test. Run them all before calling Phase 8 done.

### Wave 1 verification

- [ ] `curl -X POST -d "$(head -c 2M /dev/urandom | base64)" /api/v1/projects` returns **413 Payload Too Large**.
- [ ] Logging in, then waiting 31 min, then calling any API → 401 + "session idle".
- [ ] Logging in, then waiting 12 h, then calling any API → 401 + "session expired".
- [ ] Changing a user's role → their next API call fails until reauth.
- [ ] Calling `DELETE /users/{id}` without recent reauth → 403 + `STEP_UP_REQUIRED`.
- [ ] Inbound webhook with missing `X-Signature` → 401; with expired `X-Timestamp` → 401.
- [ ] `.md` export response has `Content-Disposition: attachment; filename="*.md"` + `nosniff`.
- [ ] User-supplied URL containing `127.0.0.1` or `169.254.*` → 400 "invalid URL".

### Wave 2 verification

- [ ] `docker inspect sentinelcore_api | grep -i User` → `"1000"`.
- [ ] `docker inspect sentinelcore_api | grep -i ReadOnly` → `true`.
- [ ] `docker exec sentinelcore_api touch /x` → "Read-only file system".
- [ ] `docker inspect sentinelcore_api | jq .[].HostConfig.CapAdd` → `null` or `[]`.
- [ ] `docker inspect sentinelcore_api | jq .[].HostConfig.SecurityOpt` → includes `no-new-privileges`.
- [ ] `nmap -Pn 77.42.34.174` → only 22, 80, 443 open.
- [ ] `ssllabs.com/ssltest` → A+ grade.
- [ ] Inside `sentinelcore_api`, `cat /proc/self/status | grep Seccomp:` → `2` (filter active).
- [ ] Memory limit: `docker stats` shows controlplane under 500 MB under load.

### Wave 3 verification

- [ ] CI passes on a PR with an introduced high-severity vuln → govulncheck fails the build.
- [ ] `trivy image ghcr.io/sentinelcore/controlplane:vX.Y.Z` → 0 HIGH+CRITICAL.
- [ ] `cosign verify ghcr.io/sentinelcore/controlplane:vX.Y.Z` → signature verified.
- [ ] `cosign download sbom ghcr.io/sentinelcore/controlplane:vX.Y.Z | jq '.components | length'` → > 0.
- [ ] Dependabot PR opened and merged automatically after CI green on a patch-level bump.
- [ ] Customer `verify-release.sh` on a shipped tag returns "all checks passed".

---

## 10. Security pitfalls to avoid

1. **Don't set `Secure: false` in dev** — use a build tag or env switch. Cookies on `localhost` over HTTP are fine with `Secure: true` modern browsers.
2. **Don't rely on `SameSite=Strict` alone for CSRF** — CSRF middleware is still required for legacy browsers and tooling.
3. **Don't implement your own rate limiter in a handler** — use `pkg/ratelimit` so limits stack properly with the middleware chain.
4. **Don't add `cap_add: NET_ADMIN` "just for debugging"** — every capability is a privilege-escalation footgun.
5. **Don't run containers as root "because it works"** — fix the Dockerfile ownership instead. UID 1000 is standard.
6. **Don't skip `govulncheck` on untouched code paths** — dependencies used transitively get patched too.
7. **Don't cache CI results across branches** — a green build on main does not prove a PR is safe.
8. **Don't use latest-tag base images** — pin by digest; the digest is the only thing a signed image can prove.
9. **Don't expose `/metrics` publicly** — that endpoint leaks architecture, versions, user counts. Bind to `127.0.0.1` or protect with basic auth.
10. **Don't put nginx, postgres, redis in the same Docker network** — network segmentation is free; use it.
11. **Don't store refresh tokens in `localStorage`** — `HttpOnly` cookie only. XSS reads localStorage trivially.
12. **Don't expire sessions by deleting DB rows without clearing Redis** — the JWT still validates by signature alone.
13. **Don't trust `X-Forwarded-For` if the reverse proxy isn't configured** — set `trusted_proxies` explicitly.
14. **Don't log request bodies** — tokens, passwords, PII leak into log aggregation.
15. **Don't disable cosign signing "temporarily"** — every gap is a release that a customer can't verify.
16. **Don't depend on Dependabot to catch everything** — monthly `govulncheck` scan as a belt-and-braces cron.
17. **Don't use `seccomp=unconfined`** — even briefly. Use a named profile or inherit the Docker default.
18. **Don't let admin endpoints share middleware with public endpoints** — explicit router grouping makes capability boundaries audit-obvious.
19. **Don't return different status codes for "wrong password" vs "user not found"** — user enumeration.
20. **Don't log `Authorization:` headers** — redact in middleware BEFORE the request hits the zerolog writer.

---

## 11. Rollout plan

### Phase 8 Wave 1 (week 1–2)

- [ ] `pkg/httpsec` + middleware chain lands, gated on an env var initially.
- [ ] Migration 041 applied to staging; observe for 48 h.
- [ ] Enable chain unconditionally in staging.
- [ ] Production rollout: deploy binary, apply migration, flip env var.
- [ ] Run the Wave 1 verification checklist end-to-end.

Revert: env var flip; binary rollback; migration 041 down.

### Phase 8 Wave 2 (week 2–3)

- [ ] Staging: new compose.yml applied; run for 1 week under realistic load.
- [ ] Seccomp profile observation: watch for blocked syscalls in `dmesg`.
- [ ] nmap external sweep confirms no unexpected ports.
- [ ] Production: rolling service-by-service (controlplane last).
- [ ] Run the Wave 2 verification checklist.

Revert: compose.yml `.bak` rollback per service.

### Phase 8 Wave 3 (week 3–4)

- [ ] CI workflow lands on a branch; verify against a few sample PRs.
- [ ] Merge CI workflow to main; first PRs use it.
- [ ] Release workflow lands; cut a test release (`v0.0.0-rc1`).
- [ ] Verify signatures and SBOMs externally.
- [ ] Announce release trust model to first enterprise customer; include verify script.

Revert: workflow files kept; disabled at the repo settings level.

### Exit criteria

- All verification checklist items green.
- External pentest confirms:
  - No open ports besides 22/80/443.
  - No information disclosure from `/metrics` or error bodies.
  - Session fixation + CSRF + clickjacking all blocked.
- At least one full release cycle (tag → build → scan → sign → SBOM → deploy → verify) completed.
- Operator runbook signed off by security officer.

---

## Appendix A — File manifest

```
pkg/httpsec/
  middleware.go, middleware_test.go
  cookies.go
  stepup.go, stepup_test.go
pkg/netutil/
  safe_url.go, safe_url_test.go

internal/controlplane/
  api/webhooks_inbound.go, webhooks_inbound_test.go
  server.go                                  (middleware chain wiring)

migrations/
  041_session_hardening.up.sql / .down.sql

.github/
  workflows/ci.yml
  workflows/release.yml
  dependabot.yml

deploy/
  docker-compose/docker-compose.yml          (rewritten for Wave 2)
  seccomp/controlplane.json, audit-service.json,
          notification-worker.json, retention-worker.json
  nginx.conf                                 (TLS 1.3, HSTS, CSP)

scripts/
  verify-release.sh                          (customer-facing)

docs/
  session-security.md
  deployment-hardening.md
  release-security.md
  platform-hardening-operator-runbook.md
```

## Appendix B — Known post-Phase-8 work (intentionally deferred)

- mTLS between services (deferred; adds operational overhead before
  we have the cert rotation story in place)
- WAF integration (nginx-level; considered enterprise-customer opt-in)
- FIPS 140-3 validated Go build (requires boringcrypto; coordinate
  with customers that actually need it)
- Kubernetes operator + admission controller (for customers on k8s;
  docker-compose remains the default deploy target)
- Hardware-backed key storage (Vault Transit / KMS) — Phase 7
  currently uses env-backed keys; the Resolver interface already
  accommodates a future Vault/KMS backend

## Appendix C — References

- Phase 7 plan: `docs/superpowers/plans/2026-04-18-phase7-data-security.md`
- OWASP ASVS 4.0.3 — used as the base checklist, mapped to this plan
- CIS Docker Benchmark v1.6.0 — used for §4.3 / §4.4 controls
- Sigstore/cosign docs — for the keyless signing flow
