# 20. Architecture Remediation — Closing Critical and High-Risk Gaps

**Version:** 1.1.0-DRAFT
**Date:** 2026-03-14
**Purpose:** Concrete redesigns that close every Critical and High-severity gap identified in the architecture review. This document supersedes the original specifications where conflicts exist.

---

## 1. Revised Architecture Decisions

### 1.1 Key Management: From Single-Key to Hierarchical Trust

**Original:** Single Ed25519 keypair per update category. Key rotation signed by the old key.

**Revised:** Three-tier key hierarchy with offline root.

```
┌─────────────────────────────────────────────────────────────────┐
│  TIER 1 — ROOT KEY (Offline, HSM-Bound)                        │
│  Purpose: signs Tier 2 key certificates ONLY                    │
│  Storage: hardware security module, never exported              │
│  Rotation: 5-year ceremony with multi-party witness             │
│  Usage: issue new signing key certificates, revoke compromised  │
│          signing keys                                           │
│                                                                  │
│  Public key: embedded in SentinelCore binary at compile time    │
│  AND stored in /etc/sentinelcore/root-trust-anchor.pub          │
│  (both locations checked — must agree)                          │
└────────────────────────┬────────────────────────────────────────┘
                         │ signs
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TIER 2 — SIGNING KEYS (Online, Per-Category)                  │
│  Purpose: signs update bundles, rule bundles, vuln intel bundles│
│  Storage: vendor build infrastructure (not HSM, but encrypted)  │
│  Rotation: annual, or immediately on suspected compromise       │
│  Validity: 18 months (overlap period for transition)            │
│                                                                  │
│  Each signing key has a certificate signed by Tier 1 root key:  │
│  {                                                               │
│    "key_id": "signing-platform-2026",                           │
│    "public_key": "ed25519:...",                                 │
│    "purpose": "platform_updates",                               │
│    "valid_from": "2026-01-01T00:00:00Z",                       │
│    "valid_until": "2027-07-01T00:00:00Z",                      │
│    "root_signature": "ed25519sig:..."                           │
│  }                                                               │
└────────────────────────┬────────────────────────────────────────┘
                         │ signs
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TIER 3 — BUNDLE SIGNATURES (Per-Artifact)                     │
│  Each bundle includes:                                          │
│  - Signing key certificate (Tier 2, carrying root signature)   │
│  - Bundle manifest signature (signed by Tier 2 key)            │
│                                                                  │
│  Verification chain:                                            │
│  1. Verify signing key certificate against root public key     │
│  2. Check signing key validity window                          │
│  3. Check signing key is not in local revocation list           │
│  4. Verify bundle manifest against signing key                 │
│  5. Verify artifact checksums against manifest                 │
└─────────────────────────────────────────────────────────────────┘
```

**Compromise recovery:**
- Tier 2 key compromised → vendor issues revocation entry signed by Tier 1 root; customer imports revocation via `sentinelcore-cli trust revoke-key --revocation-file <file>`; all bundles signed by revoked key are rejected
- Tier 1 root compromised (catastrophic) → customer manually pins new root via `sentinelcore-cli trust set-root --key <new-key> --confirm-root-rotation`; requires 3-of-5 Shamir shares to authorize; audit logged to file-based tamper-evident log

**Residual risk:** If root key is compromised AND the attacker obtains Shamir shares, the trust chain is fully compromised. Compensating control: root key ceremony requires in-person multi-party witness with video recording.

---

### 1.2 Correlation Engine: From Black Box to Defined Algorithm

**Original:** Example-only. No algorithm, no weights, no thresholds.

**Revised:** Formal multi-axis correlation with defined scoring.

```
┌─────────────────────────────────────────────────────────────────┐
│              CORRELATION ALGORITHM v1.0                          │
│                                                                  │
│  INPUT: set of SAST findings S, set of DAST findings D          │
│         for the same project and scan cycle                      │
│                                                                  │
│  For each pair (s ∈ S, d ∈ D):                                  │
│                                                                  │
│  1. CWE Axis (weight 0.40):                                     │
│     exact_cwe_match(s.cwe_id, d.cwe_id)     → 1.0              │
│     parent_cwe_match(s.cwe_id, d.cwe_id)    → 0.5              │
│     no_match                                 → 0.0              │
│                                                                  │
│  2. Parameter Axis (weight 0.25):                                │
│     exact_name(s.taint_sink_param, d.parameter) → 1.0           │
│     normalized_match(snake↔camel, aliases)       → 0.7          │
│     no_match                                     → 0.0          │
│                                                                  │
│  3. Endpoint Axis (weight 0.20):                                 │
│     route_match(s.controller_route, d.url_path):                │
│       - Extract route pattern from SAST (e.g., /api/users/:id) │
│       - Normalize DAST URL path (e.g., /api/users/123)          │
│       - Pattern match after parameter normalization → 1.0       │
│       - Prefix match (≥ 60% path segments)          → 0.6      │
│       - No match                                     → 0.0     │
│                                                                  │
│  4. Temporal Axis (weight 0.15):                                 │
│     same_scan_cycle (triggered together)        → 1.0           │
│     within_24_hours                              → 0.8          │
│     within_7_days                                → 0.5          │
│     older                                        → 0.2          │
│                                                                  │
│  correlation_score = Σ (axis_weight × axis_score)               │
│                                                                  │
│  THRESHOLDS:                                                     │
│    score ≥ 0.80 → HIGH   confidence (auto-link)                │
│    score ≥ 0.50 → MEDIUM confidence (auto-link, flag review)   │
│    score ≥ 0.30 → LOW    confidence (suggest, manual confirm)  │
│    score <  0.30 → no correlation                               │
│                                                                  │
│  COMPOSITE RISK SCORE:                                           │
│    risk = min(                                                   │
│      cvss_base                                                   │
│      × exploit_multiplier                                        │
│      × asset_criticality_weight                                  │
│      × correlation_boost,                                        │
│      10.0  ← capped at 10.0                                     │
│    )                                                             │
│                                                                  │
│    exploit_multiplier:                                            │
│      no_known_exploit          → 1.0                             │
│      exploit_exists (PoC/DB)   → 1.3                             │
│      actively_exploited (KEV)  → 1.6                             │
│                                                                  │
│    asset_criticality_weight:                                     │
│      critical → 1.4                                              │
│      high     → 1.2                                              │
│      medium   → 1.0                                              │
│      low      → 0.8                                              │
│                                                                  │
│    correlation_boost:                                            │
│      HIGH confidence correlation  → 1.2  (confirmed by both)    │
│      MEDIUM                       → 1.1                          │
│      LOW or none                  → 1.0                          │
│                                                                  │
│  DEDUPLICATION:                                                  │
│    fingerprint = SHA-256(project_id ‖ finding_type ‖ cwe_id     │
│                          ‖ file_path ‖ line_start  (SAST)       │
│                          ‖ url ‖ parameter         (DAST)       │
│                          ‖ dependency_name ‖ cve_id (SCA))      │
│    same fingerprint across scans → UPDATE last_seen, scan_count │
│    new fingerprint → INSERT new finding                          │
└─────────────────────────────────────────────────────────────────┘
```

**CWE Parent Category Map** (stored as reference data, loaded at startup):
- CWE-89 (SQL Injection) parent: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- CWE-79 (XSS) parent: CWE-74 (Injection)
- etc. — full mapping derived from MITRE CWE hierarchy

**Edge cases:**
- Multiple DAST findings match one SAST finding → create correlation group; highest-scoring pair is primary link
- SAST finding with no DAST counterpart → standalone SAST finding with risk score using base formula (no correlation boost)
- Confidence threshold overrides → admin can adjust thresholds per project in scan_config JSONB

---

### 1.3 Policy Conflict Resolution: Defined

**Original:** Unspecified.

**Revised:**

| Policy Type | Conflict Rule | Rationale |
|---|---|---|
| Scan scope (domain allowlists) | Intersection (most restrictive) | Org restricts to *.example.com; team cannot add *.other.com |
| Gate criteria (severity thresholds) | Most restrictive wins | Org says block on HIGH; team cannot override to block only CRITICAL |
| Scan profiles (passive/standard/aggressive) | Most restrictive wins | Org says passive-only; team cannot escalate to aggressive |
| Scan schedules | Most specific wins (project > team > org) | Project needs daily; org default is weekly — project wins |
| Data retention | Most restrictive wins (longest retention) | Org requires 2 years; team cannot reduce to 6 months |
| Resource quotas | Most restrictive wins (lowest limit) | Org caps at 10 concurrent scans; team cannot raise to 20 |

Decision chain returned to caller:
```json
{
  "decision": "deny",
  "reason": "severity_gate_exceeded",
  "policy_chain": [
    {"level": "org", "policy": "gate-critical-high", "result": "deny", "detail": "3 HIGH findings exceed threshold 0"},
    {"level": "team", "policy": "gate-standard", "result": "allow", "detail": "threshold is 5 HIGH"},
    {"level": "effective", "result": "deny", "rule": "most_restrictive_wins"}
  ]
}
```

---

### 1.4 SAST Sandbox: Concrete Specification

**Original:** "seccomp, AppArmor" without specifics.

**Revised:**

**Default production mode: Linux namespace isolation via Kubernetes Pod Security.**

```yaml
# SAST Worker Pod Security Context
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  fsGroup: 65534
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: Localhost
    localhostProfile: "sentinelcore/sast-worker.json"
```

**Seccomp profile (`sast-worker.json`):**
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "close", "fstat", "lstat", "stat", "lseek",
        "mmap", "mprotect", "munmap", "brk", "mremap",
        "access", "pipe", "pipe2", "dup", "dup2", "dup3",
        "fcntl", "flock", "fsync", "fdatasync",
        "openat", "newfstatat", "unlinkat", "renameat", "mkdirat",
        "getdents64", "getcwd", "readlink", "readlinkat",
        "clone", "clone3", "futex", "set_robust_list",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "exit", "exit_group",
        "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
        "eventfd2", "timerfd_create", "timerfd_settime",
        "nanosleep", "clock_gettime", "clock_nanosleep",
        "getpid", "gettid", "getuid", "getgid", "geteuid", "getegid",
        "arch_prctl", "set_tid_address", "sched_yield",
        "getrandom", "pread64", "pwrite64",
        "tgkill", "sched_getaffinity"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Explicitly denied (not in allow list):**
- `socket`, `connect`, `bind`, `listen`, `accept` — no network
- `execve`, `execveat` — no process execution after startup
- `ptrace` — no debugging/tracing
- `mount`, `umount2` — no filesystem mounting
- `setuid`, `setgid`, `setgroups` — no privilege changes

**Optional high-security mode:** gVisor (`runsc`) runtime class. Enabled via Helm value `sast.sandbox.runtime: gvisor`. Adds ~15% scan overhead. Required for environments processing adversarial code (e.g., scanning public repositories).

---

## 2. New or Changed Components

### 2.1 New: Target Verification Service (embedded in Control Plane)

Not a separate service — implemented as a verification workflow within the Control Plane API.

**Verification methods (ordered by preference):**

```
METHOD 1: DNS TXT Record
─────────────────────────
1. User requests to add scan target "app.example.com"
2. Control Plane generates verification token: "sc-verify=<random-32-hex>"
3. User adds DNS TXT record: _sentinelcore-verify.app.example.com
4. Control Plane queries DNS TXT (via system resolver or specified DNS server)
5. Match found → target verified
6. Token is single-use and expires in 72 hours
7. Air-gapped: uses internal DNS server configured in platform settings

METHOD 2: HTTP Well-Known Path
──────────────────────────────
1. User requests to add scan target "https://app.example.com"
2. Control Plane generates verification token
3. User places file at: https://app.example.com/.well-known/sentinelcore-verify
   Content: the verification token
4. Control Plane sends GET request to that URL (from control-plane network, NOT DAST worker)
5. Token match → target verified
6. IMPORTANT: this request is made from the control-plane namespace
   (has different network policy than DAST workers)
   and is NOT subject to DAST scope enforcement (chicken-and-egg)
7. Anti-abuse: verification requests rate-limited to 10/hour per user

METHOD 3: Manual Admin Approval
───────────────────────────────
1. User requests to add scan target
2. Request enters "pending_verification" state
3. platform_admin or security_director reviews and approves
4. Approval requires documented justification (stored in audit log)
5. This is the ONLY method available for internal/private targets
   where DNS TXT and HTTP verification are impractical

REVERIFICATION:
- All targets must be reverified every 90 days
- 14-day warning before expiry
- Expired targets: existing scans complete, new scans blocked
- Force-reverify: sentinelcore-cli target reverify --project <id> --target <id>
```

**Data model addition:**
```sql
CREATE TABLE core.target_verifications (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_target_id      UUID NOT NULL REFERENCES core.scan_targets(id),
    verification_method TEXT NOT NULL CHECK (verification_method IN (
                            'dns_txt', 'http_wellknown', 'admin_approval')),
    verification_token  TEXT,              -- for dns_txt and http_wellknown
    token_expires_at    TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
                            'pending', 'verified', 'failed', 'expired')),
    verified_at         TIMESTAMPTZ,
    verified_by         UUID REFERENCES core.users(id),
    approval_reason     TEXT,              -- for admin_approval method
    expires_at          TIMESTAMPTZ,       -- reverification deadline (verified_at + 90 days)
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    last_attempt_at     TIMESTAMPTZ,
    last_failure_reason TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_target_verif_expiry ON core.target_verifications(expires_at)
    WHERE status = 'verified';
```

**Orchestrator change:** Before dispatching any DAST scan, Orchestrator checks `target_verifications.status = 'verified' AND expires_at > now()`. Unverified or expired targets → scan rejected with error `TARGET_NOT_VERIFIED`.

---

### 2.2 New: NetworkPolicy Garbage Collector (CronJob)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: networkpolicy-gc
  namespace: sentinelcore-system
spec:
  schedule: "*/5 * * * *"    # Every 5 minutes
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: sentinelcore-np-gc
          containers:
            - name: gc
              image: sentinelcore/np-gc:latest
              command:
                - /sentinelcore-np-gc
                - --namespace=sentinelcore-scan-dast
                - --label-selector=sentinelcore.io/dynamic-policy=true
                - --expiry-annotation=sentinelcore.io/expires
                - --orphan-grace-period=10m
          restartPolicy: OnFailure
```

**Logic:**
```
1. List all NetworkPolicies with label sentinelcore.io/dynamic-policy=true
2. For each policy:
   a. Parse sentinelcore.io/expires annotation
   b. If expired → delete
   c. If scan-id label references a scan NOT in 'running' state → delete
   d. If no scan-id label → delete (malformed)
3. Emit metric: sentinelcore_orphaned_networkpolicies_cleaned_total
4. Alert if any policy was orphaned > 10 minutes (indicates Orchestrator cleanup failure)
```

**Orchestrator startup reconciliation:**
```
On Orchestrator leader election:
1. List all dynamic NetworkPolicies
2. List all scans in 'running' state
3. Delete any policy whose scan-id is not in running set
4. Log count of reconciled policies
```

---

### 2.3 New: Application-Level Rate Limiter (embedded in Control Plane)

Token-bucket implementation in the Control Plane API middleware:

```
Rate Limit Tiers:

TIER 1 — Per API Key:
  scan.create:     20/hour
  default:         1000/minute
  burst:           50 (above rate, drains in 3 seconds)

TIER 2 — Per User:
  scan.create:     10/hour (developer role: 5/hour)
  finding.export:  20/hour
  default:         100/minute

TIER 3 — Per Team:
  scan.create:     50/hour
  concurrent_scans: configurable (default 5)

TIER 4 — Global:
  scan.create:     200/hour (across all teams)
  This prevents total platform overload

Evaluation order: Global → Team → User → API Key
First limit hit → reject with HTTP 429 + Retry-After header

Storage: Redis with sliding window counters
Key format: ratelimit:{tier}:{entity_id}:{action}:{window}
```

---

### 2.4 Changed: Audit Log Service — HMAC Key Versioning

**Original:** HMAC key rotates quarterly; no version tracking.

**Revised:**

```sql
-- Add to audit.audit_log table
ALTER TABLE audit.audit_log ADD COLUMN hmac_key_version INTEGER NOT NULL DEFAULT 1;
```

**Key rotation procedure:**
```
1. Generate new HMAC key in Vault: vault write transit/keys/audit-hmac-v{N+1}
2. Write rotation audit entry signed by BOTH old and new keys:
   {
     "action": "audit.hmac_key_rotated",
     "details": {
       "old_version": N,
       "new_version": N+1,
       "old_key_hash": "sha256 of old key (not the key itself)",
       "new_key_hash": "sha256 of new key"
     },
     "entry_hash": "signed by old key",
     "entry_hash_new": "signed by new key",
     "hmac_key_version": N+1
   }
3. All subsequent entries use version N+1
4. Old key retained in Vault indefinitely (read-only, cannot be deleted)
5. Verification job loads correct key per entry based on hmac_key_version
```

**Vault key retention policy:**
```
Path: transit/keys/audit-hmac-v*
Policy: read-only after rotation (no delete, no update)
Minimum versions retained: ALL (never pruned)
```

---

## 3. Security Control Changes

### 3.1 DNS Rebinding Prevention in DAST Scope Enforcement

**Original:** Domain allowlist checked at request time but DNS resolution not pinned.

**Revised:** Multi-stage DNS pinning.

```
┌──────────────────────────────────────────────────────────────────┐
│            REVISED DAST SCOPE ENFORCER                           │
│                                                                  │
│  SCAN INITIALIZATION:                                            │
│  1. Resolve all approved domains to IP addresses                │
│  2. Verify ALL resolved IPs pass private-range check:           │
│     BLOCKED ranges:                                              │
│       10.0.0.0/8                                                 │
│       172.16.0.0/12                                              │
│       192.168.0.0/16                                             │
│       127.0.0.0/8                                                │
│       169.254.0.0/16       (link-local)                         │
│       169.254.169.254/32   (cloud metadata — explicit)          │
│       ::1/128              (IPv6 loopback)                      │
│       fc00::/7             (IPv6 ULA)                           │
│       fe80::/10            (IPv6 link-local)                    │
│       100.64.0.0/10        (CGNAT)                              │
│       0.0.0.0/8            (current network)                    │
│  3. Store pinned IP set: {domain → [ip1, ip2, ...]}            │
│  4. Generate NetworkPolicy using PINNED IPs (not domains)       │
│                                                                  │
│  EVERY OUTBOUND REQUEST:                                         │
│  1. Extract target domain from URL                               │
│  2. Check domain is in approved allowlist                        │
│  3. Resolve domain to IP (fresh resolution)                     │
│  4. Compare resolved IP to pinned IP set for that domain         │
│  5. IF resolved IP ∉ pinned set:                                │
│     a. Check if new IP passes private-range check               │
│     b. IF new IP is private → BLOCK, ALERT, INCREMENT           │
│        sentinelcore_scope_violation_total{type="dns_rebind"}    │
│     c. IF new IP is public and in approved CIDR → allow         │
│        (legitimate DNS load balancing), add to pinned set       │
│     d. IF new IP is public but NOT in approved CIDR → BLOCK     │
│  6. Verify port is in allowed set                                │
│  7. Verify path prefix matches (if configured)                  │
│  8. Verify protocol is HTTP or HTTPS only                       │
│                                                                  │
│  REDIRECT HANDLING:                                              │
│  Every HTTP 3xx redirect is treated as a NEW request:           │
│  - Extract Location header                                       │
│  - Apply ALL checks above to the redirect target                │
│  - Maximum redirect chain: 5 hops                               │
│  - Cross-domain redirect (to domain not in allowlist) → BLOCK   │
│                                                                  │
│  DNS RESOLVER:                                                   │
│  - DAST worker uses a dedicated DNS resolver (not system)       │
│  - Resolver configured in worker config (default: Kubernetes    │
│    CoreDNS for internal targets, or specified upstream)          │
│  - DNS responses cached for TTL or max 60 seconds               │
│  - DNS over HTTPS (DoH) NOT used (adds opacity)                │
└──────────────────────────────────────────────────────────────────┘
```

**Residual risk:** A target with a legitimate CDN may have many IPs. The pinned set grows but never exceeds a configurable maximum (default: 50 IPs per domain). Exceeding this limit triggers a warning and requires admin review.

---

### 3.2 Worker Result Message Integrity

**Original:** Workers publish to NATS with mTLS authentication but no message-level signing.

**Revised:**

```
Worker Result Message Format:
{
  "header": {
    "message_id": "uuid",
    "scan_id": "uuid",
    "worker_id": "dast-worker-3",
    "worker_certificate_fingerprint": "sha256:...",  // of mTLS cert
    "timestamp": "2026-03-14T10:30:00Z",
    "message_type": "scan.result.dast",
    "sequence": 42,
    "total_expected": 150
  },
  "payload": { ... finding data ... },
  "signature": "ed25519sig:..."  // signed with worker's ephemeral key
}

Worker Ephemeral Signing Key:
- Generated at worker pod startup
- Public key registered with Orchestrator during worker check-in
- Key lives only in memory, destroyed on pod termination
- Orchestrator stores: {worker_id → public_key, registered_at, scan_ids}

Correlation Engine Verification:
1. Extract worker_id from header
2. Look up registered public key for that worker
3. Verify signature over (header + payload)
4. Verify scan_id was dispatched to this worker_id (check Orchestrator records)
5. Verify timestamp is within acceptable clock skew (±30 seconds)
6. Rejection → alert, quarantine message, do NOT process
```

---

### 3.3 CI/CD Webhook Signature Verification

**Original:** Not specified.

**Revised:**

```sql
-- Add to cicd schema
CREATE TABLE cicd.webhook_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    platform        TEXT NOT NULL CHECK (platform IN (
                        'github', 'gitlab', 'jenkins', 'azure_devops', 'generic')),
    webhook_url     TEXT NOT NULL,       -- the endpoint path
    -- Signature verification config
    signature_method TEXT NOT NULL CHECK (signature_method IN (
                        'hmac_sha256', 'token_header', 'basic_auth', 'none')),
    signature_header TEXT,               -- e.g., 'X-Hub-Signature-256' for GitHub
    secret_vault_path TEXT,              -- path in Vault to HMAC secret
    -- Filtering
    event_filter    TEXT[] NOT NULL DEFAULT '{push, pull_request}',
    branch_filter   TEXT[],              -- regex patterns for allowed branches
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID NOT NULL REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Platform-specific verification:**

```
GitHub:
  Header: X-Hub-Signature-256
  Verification: HMAC-SHA256(secret, request_body) == header value
  Required: YES (reject unsigned)

GitLab:
  Header: X-Gitlab-Token
  Verification: constant-time comparison with stored token
  Required: YES

Jenkins:
  Method: HMAC-SHA256 via shared secret (Jenkins Webhook Relay plugin)
  Fallback: IP allowlist for Jenkins server
  Required: HMAC preferred, IP allowlist as fallback

Azure DevOps:
  Header: Basic Auth on webhook URL
  Verification: validate credentials
  Required: YES

Generic:
  Configurable: header name + HMAC algorithm + secret
  Default: reject all unsigned requests
  Override: allow unsigned with explicit platform_admin config + audit warning
```

**Default behavior:** `signature_method = 'none'` is NOT allowed for new webhook configs. Platform admin can override by setting `cicd.allow_unsigned_webhooks: true` in platform config (audit logged, compliance warning generated).

---

## 4. Data Model Changes

### 4.1 Evidence Integrity Fields

```sql
-- Add to findings.findings
ALTER TABLE findings.findings ADD COLUMN evidence_hash TEXT;
ALTER TABLE findings.findings ADD COLUMN evidence_size BIGINT;
ALTER TABLE findings.findings ADD COLUMN evidence_verified_at TIMESTAMPTZ;
ALTER TABLE findings.findings ADD COLUMN evidence_integrity TEXT
    CHECK (evidence_integrity IN ('verified', 'unverified', 'compromised'));
```

### 4.2 Finding Immutability Trigger

```sql
-- Prevent UPDATE on immutable finding fields
CREATE OR REPLACE FUNCTION findings.enforce_finding_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.title IS DISTINCT FROM NEW.title
       OR OLD.description IS DISTINCT FROM NEW.description
       OR OLD.cwe_id IS DISTINCT FROM NEW.cwe_id
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.confidence IS DISTINCT FROM NEW.confidence
       OR OLD.file_path IS DISTINCT FROM NEW.file_path
       OR OLD.line_start IS DISTINCT FROM NEW.line_start
       OR OLD.url IS DISTINCT FROM NEW.url
       OR OLD.http_method IS DISTINCT FROM NEW.http_method
       OR OLD.parameter IS DISTINCT FROM NEW.parameter
       OR OLD.code_snippet IS DISTINCT FROM NEW.code_snippet
       OR OLD.dependency_name IS DISTINCT FROM NEW.dependency_name
       OR OLD.dependency_version IS DISTINCT FROM NEW.dependency_version
       OR OLD.cve_ids IS DISTINCT FROM NEW.cve_ids
       OR OLD.evidence_ref IS DISTINCT FROM NEW.evidence_ref
       OR OLD.evidence_hash IS DISTINCT FROM NEW.evidence_hash
       OR OLD.fingerprint IS DISTINCT FROM NEW.fingerprint
       OR OLD.finding_type IS DISTINCT FROM NEW.finding_type
       OR OLD.first_seen_at IS DISTINCT FROM NEW.first_seen_at
       OR OLD.rule_id IS DISTINCT FROM NEW.rule_id
    THEN
        RAISE EXCEPTION 'Immutable finding fields cannot be modified. finding_id=%', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_immutability
    BEFORE UPDATE ON findings.findings
    FOR EACH ROW
    EXECUTE FUNCTION findings.enforce_finding_immutability();
```

**Mutable fields (allowed to UPDATE):**
- `status` — changed via triage workflow
- `last_seen_at` — updated on rescan
- `scan_count` — incremented on rescan
- `correlated_finding_ids` — updated by Correlation Engine
- `correlation_confidence` — updated by Correlation Engine
- `risk_score` — recalculated on new intelligence
- `cvss_score`, `cvss_vector`, `epss_score` — updated by vuln intel enrichment
- `evidence_verified_at`, `evidence_integrity` — updated by verification
- `tags` — user-editable metadata
- `updated_at` — automatic

### 4.3 Audit Log HMAC Key Version

```sql
ALTER TABLE audit.audit_log ADD COLUMN hmac_key_version INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_audit_hmac_version ON audit.audit_log(hmac_key_version);
```

### 4.4 Scan Target Cross-Validation Constraint

```sql
-- Ensure scan_target belongs to same project as scan_job
-- Enforced at application level (Orchestrator) because composite FK
-- across different schemas is complex. Belt-and-suspenders:

CREATE OR REPLACE FUNCTION scans.validate_scan_target_project()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.scan_target_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM core.scan_targets
            WHERE id = NEW.scan_target_id
              AND project_id = NEW.project_id
        ) THEN
            RAISE EXCEPTION 'scan_target % does not belong to project %',
                NEW.scan_target_id, NEW.project_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_validate_scan_target
    BEFORE INSERT OR UPDATE ON scans.scan_jobs
    FOR EACH ROW
    EXECUTE FUNCTION scans.validate_scan_target_project();
```

### 4.5 Soft Delete Standardization

```sql
-- Add to all deletable entities
ALTER TABLE core.projects ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE core.scan_targets ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE auth.auth_configs ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE cicd.webhook_configs ADD COLUMN deleted_at TIMESTAMPTZ;

-- All queries add: WHERE deleted_at IS NULL
-- Hard delete only via retention enforcement with platform_admin audit log
```

---

## 5. Operational Workflow Changes

### 5.1 Vault Unseal Runbook (Operational Specification)

```
VAULT UNSEAL PROCEDURE — SENTINELCORE
======================================

TRIGGER: Vault enters sealed state (pod restart, node failure, manual seal)
ALERT:   sentinelcore_vault_sealed → CRITICAL (PagerDuty / on-call)
SLA:     Unseal within 30 minutes of alert

PREREQUISITES:
- 5 key holders designated by role (not individual name):
  1. Platform Operations Lead
  2. Security Operations Lead
  3. Infrastructure Lead
  4. CISO / Deputy CISO
  5. Engineering Director
- Each has one Shamir share stored on encrypted USB
- Backup holders: one backup per primary holder, shares on separate media

PROCEDURE:
1. On-call operator receives CRITICAL alert
2. Operator verifies Vault is sealed: sentinelcore-cli status vault
3. Operator initiates unseal request via secure channel:
   - Primary: internal incident management system (ticket)
   - Fallback: phone tree to key holders
4. Minimum 3 of 5 holders respond within 15 minutes
   - If fewer than 3 at 15 minutes: escalate to backup holders
5. Each holder authenticates via corporate SSO
6. Each holder provides their share via:
   - Primary: sentinelcore-cli vault unseal --share <share>
     (executed from holder's authenticated workstation)
   - Fallback: read share to operator over phone (voice verification)
7. After 3rd share: Vault unseals
8. Operator verifies services recover: sentinelcore-cli status services
9. Operator closes incident ticket with unseal timestamp

LOGGING:
- Unseal event logged to file: /var/log/sentinelcore/vault-unseal.log
  (file-based because audit DB depends on Vault)
- File log format: timestamp, operator_id, holder_ids, duration
- File log is append-only (chattr +a on Linux)

DRILL:
- Quarterly unseal drill in staging environment
- Annual key holder rotation ceremony:
  1. Generate new Shamir shares
  2. Distribute to current holders
  3. Verify by unsealing staging Vault
  4. Destroy old shares
  5. Document ceremony (date, attendees, verification result)
```

### 5.2 Orphan Resource Reconciliation

Beyond NetworkPolicy GC, add reconciliation for all ephemeral resources:

```
ORCHESTRATOR STARTUP RECONCILIATION:
1. NetworkPolicies: delete policies for non-running scans
2. Ephemeral PVCs: delete PVCs for completed/failed scan pods
3. Scan jobs in 'running' state with no worker heartbeat > 5 min:
   → transition to 'failed' with reason 'worker_lost'
   → if retry_count < max_retries → re-dispatch
4. Scan jobs in 'dispatched' state for > 10 min with no worker pickup:
   → re-dispatch to queue

PERIODIC RECONCILIATION (every 10 minutes):
1. Check all 'running' scans have recent heartbeat (< 2 min)
2. Check all dynamic NetworkPolicies have matching running scan
3. Check NATS consumer lag — alert if > 1000 pending messages
```

---

## 6. Bootstrap and Trust Establishment Flow

```
┌──────────────────────────────────────────────────────────────────┐
│           SENTINELCORE BOOTSTRAP SEQUENCE                        │
│                                                                  │
│  PHASE 1: INFRASTRUCTURE (automated by Helm)                    │
│  ──────────────────────────────────────────                     │
│  1. Helm creates namespaces with default-deny NetworkPolicies   │
│  2. PostgreSQL pod starts, creates empty database               │
│  3. MinIO pod starts, creates buckets                           │
│  4. NATS pod starts, creates streams                            │
│  5. Redis pod starts                                            │
│                                                                  │
│  PHASE 2: VAULT INITIALIZATION (requires human operator)        │
│  ──────────────────────────────────────────                     │
│  6. Vault pod starts in uninitialized state                     │
│  7. Operator runs: sentinelcore-cli vault init                  │
│     → Generates 5 Shamir key shares (displayed ONCE)            │
│     → Generates root token (displayed ONCE)                     │
│     → Operator records shares on separate media                 │
│  8. Operator provides 3 shares to unseal                        │
│  9. Vault is now operational                                    │
│                                                                  │
│  PHASE 3: TRUST ANCHOR IMPORT (requires human operator)         │
│  ──────────────────────────────────────────                     │
│  10. Operator imports root trust anchor public key:             │
│      sentinelcore-cli trust init \                              │
│        --root-key /path/to/root-trust-anchor.pub               │
│      → Key stored in Vault AND written to ConfigMap             │
│      → Both locations must agree (verified at every startup)    │
│  11. Operator imports initial signing key certificate:          │
│      sentinelcore-cli trust import-signing-cert \               │
│        --cert /path/to/signing-cert.json                        │
│      → Verified against root key                                │
│      → Stored in Vault                                          │
│                                                                  │
│  PHASE 4: SCHEMA AND SEED DATA (automated, Helm pre-install)   │
│  ──────────────────────────────────────────                     │
│  12. Init job runs: sentinelcore-db-init                        │
│      → Creates all schemas (core, scans, findings, etc.)        │
│      → Inserts system policies (immutable defaults)             │
│      → Inserts CWE parent category map                          │
│      → Creates default organization                             │
│  13. Rule init job: sentinelcore-rules-init                     │
│      → Loads built-in rule sets (embedded in container image)   │
│                                                                  │
│  PHASE 5: FIRST ADMIN (requires human operator)                 │
│  ──────────────────────────────────────────                     │
│  14. Operator runs:                                             │
│      sentinelcore-cli bootstrap create-admin \                  │
│        --username admin \                                       │
│        --email admin@example.com                                │
│      → Creates platform_admin user with temporary password      │
│      → Password displayed ONCE, must be changed on first login  │
│      → This command can only run ONCE (blocked after first use) │
│      → Guarded by: database flag bootstrap_completed=false      │
│                                                                  │
│  PHASE 6: SERVICES START (automated by Helm)                   │
│  ──────────────────────────────────────────                     │
│  15. Control Plane starts:                                      │
│      → Verifies database schema version                         │
│      → Verifies Vault is unsealed                               │
│      → Verifies root trust anchor matches ConfigMap AND Vault   │
│      → Verifies time synchronization                            │
│      → If any check fails → crash with explicit error           │
│  16. All other services start                                   │
│  17. Health check job verifies all services are healthy          │
│                                                                  │
│  PHASE 7: POST-BOOTSTRAP (operator, optional)                  │
│  ──────────────────────────────────────────                     │
│  18. Admin logs in, changes password                            │
│  19. Admin configures IdP (OIDC/LDAP/SAML)                     │
│  20. Admin imports initial vuln intel bundle (if air-gapped)    │
│  21. Admin creates first project and team                       │
│  22. Admin configures backup schedule                           │
│  23. Admin verifies monitoring dashboards                       │
│                                                                  │
│  BOOTSTRAP COMPLETE                                              │
│  Set database flag: bootstrap_completed=true                    │
│  Audit entry: system.bootstrap_completed                        │
└──────────────────────────────────────────────────────────────────┘
```

**Bootstrap lockout:**
```sql
CREATE TABLE core.system_state (
    key             TEXT PRIMARY KEY,
    value           JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Set during Phase 5:
INSERT INTO core.system_state (key, value) VALUES
    ('bootstrap_completed', '{"completed": true, "completed_at": "...", "admin_user": "..."}');

-- create-admin command checks this flag and refuses to run if true
```

---

## 7. Key Management and Recovery Flow

(See Section 1.1 for the three-tier hierarchy. This section covers operational flows.)

### 7.1 Normal Signing Key Rotation

```
1. Vendor generates new Tier 2 signing key pair
2. Vendor creates signing key certificate, signed by Tier 1 root:
   {
     "key_id": "signing-platform-2027",
     "public_key": "ed25519:...",
     "purpose": "platform_updates",
     "valid_from": "2027-01-01T00:00:00Z",
     "valid_until": "2028-07-01T00:00:00Z",
     "replaces": "signing-platform-2026",
     "root_signature": "ed25519sig:..."
   }
3. New certificate distributed with next update bundle
4. Customer Update Manager:
   a. Verifies certificate against root public key
   b. Stores new certificate in Vault
   c. Both old and new certs valid during overlap period
   d. After old cert expires, bundles signed with it are rejected
```

### 7.2 Signing Key Compromise Response

```
SIGNING KEY COMPROMISED (Tier 2):
1. Vendor issues revocation record, signed by Tier 1 root:
   {
     "action": "revoke",
     "key_id": "signing-platform-2026",
     "reason": "key_compromise",
     "revoked_at": "2026-06-15T00:00:00Z",
     "root_signature": "ed25519sig:..."
   }
2. Revocation distributed via:
   a. HTTPS endpoint (connected customers pull immediately)
   b. Emergency bundle (air-gapped customers import manually)
   c. Email/support notification to all customers
3. Customer imports revocation:
   sentinelcore-cli trust revoke-key --revocation-file revocation.json
   → Verified against root key
   → Key added to local revocation list in Vault
   → All bundles signed by revoked key are rejected going forward
   → Already-applied updates are NOT rolled back (they were valid at time of application)
4. Vendor issues new signing key certificate (see 7.1)
```

### 7.3 Root Key Compromise Response (Catastrophic)

```
ROOT KEY COMPROMISED (Tier 1):
1. This is a catastrophic event requiring manual intervention
2. Vendor generates new root key pair on new HSM
3. Vendor communicates new root public key via:
   a. Vendor website (HTTPS, EV certificate)
   b. Direct communication to customer contacts
   c. Signed with PGP key of vendor security team (separate trust chain)
4. Customer manually pins new root key:
   sentinelcore-cli trust set-root \
     --key /path/to/new-root-key.pub \
     --confirm-root-rotation \
     --shamir-shares <share1> <share2> <share3>
   → Requires 3-of-5 Shamir shares (catastrophic operation)
   → Old root key moved to revocation list
   → All signing key certificates issued by old root are revoked
   → New signing key certificates must be imported
5. Audit: logged to file-based tamper-evident log AND database audit log
```

---

## 8. Scope Enforcement Hardening Flow

(Combines DNS rebinding fix from Section 3.1 with full enforcement pipeline.)

```
┌──────────────────────────────────────────────────────────────────┐
│           COMPLETE DAST SCOPE ENFORCEMENT PIPELINE               │
│                                                                  │
│  LAYER 1: TARGET VERIFICATION (Control Plane)                   │
│  ├── Target ownership proven via DNS TXT / HTTP / admin approval│
│  ├── Verification valid for 90 days                             │
│  └── Unverified targets → scans blocked                         │
│                                                                  │
│  LAYER 2: POLICY EVALUATION (Orchestrator → Policy Engine)      │
│  ├── Scan scope checked against team + org policies             │
│  ├── Domain must be in policy allowlist                         │
│  ├── Scan profile must be within policy limits                  │
│  └── Policy denial → scan rejected before dispatch              │
│                                                                  │
│  LAYER 3: DNS PINNING (Orchestrator, pre-dispatch)              │
│  ├── Resolve all approved domains to IP addresses               │
│  ├── Verify all IPs pass private-range blocklist                │
│  ├── Pin IP set for scan duration                               │
│  └── Generate Kubernetes NetworkPolicy with pinned IPs          │
│                                                                  │
│  LAYER 4: NETWORK POLICY (Kubernetes, enforced by CNI)          │
│  ├── Dynamic NetworkPolicy allows egress ONLY to pinned IPs    │
│  ├── All other egress denied at network level                   │
│  ├── NetworkPolicy created BEFORE worker pod starts scan        │
│  └── Even if application-level checks fail, network blocks      │
│                                                                  │
│  LAYER 5: APPLICATION SCOPE CHECK (DAST Worker, per-request)    │
│  ├── Domain allowlist check                                     │
│  ├── Fresh DNS resolution + pinned IP comparison                │
│  ├── Rebinding detection (new IP → blocked if private)          │
│  ├── Port allowlist check                                       │
│  ├── Path prefix check                                          │
│  ├── Protocol check (HTTP/HTTPS only)                           │
│  ├── Redirect chain validation (max 5, no cross-domain escape)  │
│  └── Any violation → request BLOCKED, metric incremented, logged│
│                                                                  │
│  LAYER 6: MONITORING (Continuous)                                │
│  ├── sentinelcore_scope_violation_total metric                  │
│  ├── ANY increment → CRITICAL alert                             │
│  ├── Scan automatically paused on 3+ violations                 │
│  └── Forensic log of every violation (full request details)     │
└──────────────────────────────────────────────────────────────────┘

Scope enforcement is the ONLY part of SentinelCore where defense-in-depth
uses 6 independent layers. Failure of any single layer does not compromise
scope. An attacker would need to bypass ALL 6 layers simultaneously.
```

---

## 9. Evidence Integrity and Immutability Design

### 9.1 Evidence Lifecycle with Integrity

```
EVIDENCE CREATION (during scan):
  1. Worker produces evidence artifact (code snippet, HTTP trace, screenshot)
  2. Worker computes SHA-256 hash of artifact bytes
  3. Worker uploads artifact to MinIO with metadata:
     - Content-Type
     - x-amz-meta-sha256: <hash>
     - x-amz-meta-scan-id: <scan_id>
     - x-amz-meta-finding-id: <finding_id>
     - x-amz-meta-created-at: <timestamp>
  4. MinIO returns version ID (versioning enabled)
  5. Worker publishes finding to NATS with:
     - evidence_ref: "evidence/{project_id}/{scan_id}/{finding_type}/{finding_id}/..."
     - evidence_hash: "sha256:<hash>"
     - evidence_size: <bytes>
  6. Correlation Engine writes finding with evidence fields to PostgreSQL

EVIDENCE READ (analyst, report, export):
  1. Service reads evidence_ref and evidence_hash from findings table
  2. Service downloads artifact from MinIO
  3. Service computes SHA-256 of downloaded bytes
  4. Service compares computed hash with stored evidence_hash
  5. IF MATCH:
     → Return artifact
     → Update evidence_verified_at = now(), evidence_integrity = 'verified'
  6. IF MISMATCH:
     → Return error: EVIDENCE_INTEGRITY_COMPROMISED
     → Update evidence_integrity = 'compromised'
     → Emit metric: sentinelcore_evidence_integrity_failure_total
     → CRITICAL alert
     → Audit log: evidence.integrity_failure

EVIDENCE IN COMPLIANCE REPORTS:
  1. Report generation MUST verify all included evidence
  2. Report includes evidence hash for each artifact
  3. If ANY evidence fails integrity check:
     → Report includes warning: "Evidence integrity compromised for finding <id>"
     → Report marked with: integrity_status = 'partial'
     → Alert generated

EVIDENCE RETENTION:
  1. Evidence follows retention policy (default: 1 year)
  2. Before deletion:
     → Compute and verify hash one final time
     → Write archive record: {evidence_ref, hash, size, finding_id, archived_at}
     → Audit log: evidence.archived
  3. For compliance-critical deployments:
     → MinIO Object Lock (WORM) enabled: governance or compliance mode
     → Objects cannot be deleted until lock expires
     → Lock duration matches retention policy
```

### 9.2 MinIO WORM Configuration (compliance mode)

```yaml
# Helm values for compliance-critical deployments
minio:
  objectLocking:
    enabled: true
  buckets:
    evidence:
      objectLocking:
        mode: GOVERNANCE        # can be overridden by admin with special permission
        # or: COMPLIANCE        # cannot be overridden by anyone, even admin
        retentionDays: 365
    audit-archives:
      objectLocking:
        mode: COMPLIANCE
        retentionDays: 2555     # 7 years
```

---

## 10. Break-Glass and Emergency Access Model

```
┌──────────────────────────────────────────────────────────────────┐
│           BREAK-GLASS EMERGENCY ACCESS                           │
│                                                                  │
│  PURPOSE: Regain platform access when all normal access paths   │
│  are unavailable (all admins locked out, IdP down, etc.)        │
│                                                                  │
│  ACTIVATION REQUIRES:                                            │
│  - Physical or SSH access to a cluster node                     │
│  - 3 of 5 Shamir shares (from break-glass key set)             │
│  - These are SEPARATE from Vault unseal shares                  │
│    (different shares, potentially different holders)             │
│                                                                  │
│  PROCEDURE:                                                      │
│  1. Operator accesses cluster node (SSH or console)             │
│  2. Runs: sentinelcore-cli emergency-access activate \          │
│           --share <share1> --share <share2> --share <share3>    │
│  3. System generates:                                            │
│     - Temporary local account: _breakglass_<timestamp>          │
│     - Random 32-character password (displayed ONCE)             │
│     - Role: platform_admin                                      │
│     - Session expiry: 4 hours (non-renewable)                   │
│  4. Operator logs in via API or minimal CLI                     │
│  5. Operator performs recovery actions:                          │
│     - Unlock admin accounts                                     │
│     - Reset passwords                                            │
│     - Reconfigure IdP                                            │
│     - Unseal Vault (if needed)                                  │
│  6. After 4 hours OR manual deactivation:                       │
│     sentinelcore-cli emergency-access deactivate                │
│     → Account disabled and deleted                              │
│     → All sessions invalidated                                  │
│                                                                  │
│  SECURITY CONTROLS:                                              │
│  - Break-glass account has NO access to:                        │
│    • Vault secrets (cannot read credentials)                    │
│    • Evidence store (cannot read findings evidence)             │
│    • Audit log deletion (cannot tamper with audit trail)        │
│  - Break-glass account CAN:                                     │
│    • Create/unlock user accounts                                │
│    • Reset passwords                                             │
│    • Modify platform configuration                              │
│    • View service health                                        │
│                                                                  │
│  LOGGING:                                                        │
│  - ALL break-glass actions logged to BOTH:                      │
│    1. File-based append-only log:                               │
│       /var/log/sentinelcore/breakglass-audit.log                │
│       (chattr +a, survives database unavailability)             │
│    2. Database audit log (when available)                       │
│  - Log entries include: timestamp, action, IP, operator identity│
│  - Break-glass activation alert sent to ALL configured          │
│    notification channels (if available)                         │
│                                                                  │
│  ANTI-ABUSE:                                                     │
│  - Maximum 3 break-glass activations per 24 hours               │
│  - Each activation requires fresh Shamir shares                 │
│  - Failed share verification: 5 attempts then 1-hour lockout   │
│  - Every activation generates a compliance incident report      │
│    that must be reviewed and closed by security_director        │
│                                                                  │
│  SHAMIR SHARE MANAGEMENT:                                        │
│  - Break-glass shares generated during bootstrap (Phase 2)      │
│  - Separate from Vault unseal shares (defense in depth:         │
│    Vault compromise doesn't grant break-glass access)           │
│  - Stored on encrypted USB, separate from Vault shares          │
│  - Annual rotation ceremony (same process as Vault shares)      │
└──────────────────────────────────────────────────────────────────┘
```

**Implementation:**

```sql
-- Break-glass state tracking (separate from main auth)
CREATE TABLE core.breakglass_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        TEXT NOT NULL,
    activated_by    TEXT NOT NULL,          -- operator identity from share ceremony
    activated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    deactivated_at  TIMESTAMPTZ,
    activation_ip   INET NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'expired', 'deactivated'))
);

-- Rate limiting enforcement
CREATE TABLE core.breakglass_attempts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attempted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    result          TEXT NOT NULL CHECK (result IN ('success', 'failed')),
    failure_reason  TEXT,
    source_ip       INET NOT NULL
);
```

---

## 11. Trade-offs These Fixes Introduce

| Fix | Trade-off | Impact | Acceptable? |
|---|---|---|---|
| **Three-tier key hierarchy** | Adds operational complexity to update process; vendor must maintain HSM infrastructure; key ceremonies require coordination | Medium complexity increase | Yes — supply chain security is non-negotiable for enterprise customers |
| **Target ownership verification** | Adds friction to onboarding new scan targets; DNS TXT/HTTP verification requires target owner cooperation; 90-day reverification adds recurring burden | Onboarding time increases by 1-24 hours per target | Yes — prevents catastrophic mis-targeting; manual approval path exists for difficult cases |
| **DNS pinning** | Legitimate CDN IP rotation may trigger false blocks; pinned IP set can grow large for CDN-backed targets; requires monitoring and tuning per-target | Possible scan interruption for CDN targets (mitigated by public-IP growth allowance) | Yes — DNS rebinding is a real attack vector; CDN case handled by allowing public IP additions |
| **6-layer scope enforcement** | Performance overhead: 5-10% additional latency per DAST request due to multiple checks; operational complexity in debugging scope issues | Minor scan slowdown | Yes — scope enforcement is the highest-criticality safety feature |
| **Finding immutability trigger** | Cannot "fix" incorrect findings in place; must create new finding and mark old as false_positive; slightly more complex data model | Analyst workflow requires one extra step for corrections | Yes — immutability is required for compliance evidence chain |
| **HMAC key versioning** | Vault must retain all historical HMAC keys forever; small storage cost; verification slightly slower (key lookup per entry) | Negligible storage; ~1ms per verification | Yes — audit integrity verification across key rotations is mandatory |
| **Worker message signing** | Adds ~2ms per result message for sign/verify; requires ephemeral key registration workflow during worker startup | Negligible performance; minor startup complexity | Yes — prevents compromised worker from injecting false findings |
| **Break-glass with separate Shamir shares** | Two separate Shamir share sets to manage (Vault + break-glass); more ceremony overhead; more secure USB drives to safeguard | Increased operational ceremony burden | Yes — separation ensures Vault compromise doesn't grant admin access and vice versa |
| **Application-level rate limiting** | Legitimate burst workloads (CI/CD mass trigger after deploy) may be throttled; requires tuning per customer | May require customer-specific rate limit adjustment | Yes — default limits are generous; configurable per team |
| **NetworkPolicy GC CronJob** | Additional CronJob running every 5 minutes; requires RBAC for NetworkPolicy management; adds operational surface | Minimal resource usage; one more component to monitor | Yes — orphaned policies are a real risk if Orchestrator crashes |
| **Bootstrap sequence** | First-run requires human operator for Vault init, trust anchor import, and admin creation; cannot be fully automated | 30-60 minutes of operator time for initial setup | Yes — trust establishment MUST involve human verification; cannot be automated without creating a bootstrap trust problem |

**Net assessment:** These fixes increase operational complexity by approximately 20% but close all Critical and High-severity gaps. The primary burden falls on initial deployment (bootstrap) and periodic ceremonies (key rotation, reverification). Day-to-day operation is minimally affected. The correlation algorithm, scope enforcement, and evidence integrity fixes improve the platform's core value proposition and compliance posture without measurable user-facing impact.

<function_calls>
<invoke name="TodoWrite">
<parameter name="todos">[{"content": "Write remediation sections 1-4: Revised decisions, new components, security controls, data model", "status": "completed", "activeForm": "Writing remediation sections 1-4"}, {"content": "Write remediation sections 5-8: Operational workflows, bootstrap, key mgmt, scope enforcement", "status": "completed", "activeForm": "Writing remediation sections 5-8"}, {"content": "Write remediation sections 9-11: Evidence integrity, break-glass, trade-offs", "status": "completed", "activeForm": "Writing remediation sections 9-11"}]