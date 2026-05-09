# DAST Authentication & CAPTCHA Bypass — Banking-Grade Design Spec

**Status:** Design draft, awaiting review
**Owner:** Huseyin
**Target:** Enable authenticated DAST scanning of CAPTCHA-protected applications in banking environments without compromising the security guarantees that make SentinelCore deployable in regulated tier-1 financial institutions.
**Date:** 2026-05-04
**Version:** 1.0

---

## 1. Goals & non-goals

### 1.1 Goals

- Enable end-to-end DAST scans of authenticated, CAPTCHA-protected web applications owned by the customer (banks scanning their own staging or production-mirror environments).
- Preserve the existing authbroker contract (`Strategy` interface) so that DAST scan jobs flowing through `internal/dast/worker.go` need no fundamental rewrite.
- Provide three layered solutions a customer can mix and match:
  - **A — Session import** (manual cookie/header paste; lowest cost, highest trust transfer to user).
  - **B — Recorded login replay** (browser-based recording captures action list and final session; supports both automatable and one-shot refresh modes).
  - **C — Scanner bypass token** (HMAC-signed header that customer staging back-ends can opt into to skip CAPTCHA for verified scanner traffic).
- Meet, with auditable evidence, the regulatory controls required by tier-1 banking deployments: BDDK Bilgi Sistemleri Yönetmeliği, KVKK, PCI-DSS 4.0 §3/§4/§8/§10, ISO 27001 A.9 + A.12, SOC 2 Type II, NIST 800-53 IA-5 + AC-6.
- Provide cryptographic, audit, and operational guarantees strong enough that a SentinelCore deployment passes a banking customer's external penetration test, internal audit committee review, and BDDK on-site inspection.

### 1.2 Non-goals

- **Programmatic CAPTCHA solving.** SentinelCore will not integrate with 2Captcha, Anti-Captcha, or any solver-as-a-service. The legal and ethical risks of automated CAPTCHA defeat are unacceptable in a tier-1 banking deployment, and the failure modes (rate limit retaliation, ToS violations, unintended traffic into shared CAPTCHA pools) cannot be controlled. Banking customers who need to scan CAPTCHA-protected flows do so via Approach C in their own staging where they own the CAPTCHA service.
- **Attacker-side tooling.** Recordings, bundles, and bypass tokens are scoped exclusively to assets the customer owns or has authorization to test. Multi-tenant safeguards (Section 10) enforce this.
- **Scanning unowned third-party services.** No design decision in this spec assumes the customer can or should solve CAPTCHA for third-party assets even with a customer's recording.
- **MFA push-bombing or session hijacking of unrelated users.** Recordings capture only the recording user's own session; replay against another user's account is explicitly prevented by Section 6.
- **Network-level scanning.** This spec covers application-layer authenticated DAST only.

### 1.3 Out-of-scope follow-ups

- Browser session sharing across scan workers (Approach D from the brainstorm) — defer to a later phase if warranted by customer demand. RecordedLoginStrategy + customer-side bypass header covers the same use cases at lower complexity.
- Native mobile-app DAST authentication (mobile apps require a separate recording substrate).
- WebAuthn / passkey replay — physical security keys cannot be replayed by design; documented as a permanent limitation, not a gap.

---

## 2. Threat model & compliance matrix

### 2.1 Assets

| Asset | Sensitivity | Lifetime | Storage |
|-------|-------------|----------|---------|
| Login credentials (user / password / OAuth2 client secret) | Critical (PCI-DSS req 3) | Until customer deletes | HashiCorp Vault, encrypted with customer-controlled key |
| Session bundle (cookies, JWTs, localStorage, response headers) | Critical — equals an active customer session | TTL ≤ 24h, hard cap 7 days | `dast_auth_bundles` table, AES-256-GCM with envelope-encrypted DEK |
| Recording action list (URLs visited, fields filled, button selectors) | High — exposes app internals + login flow secrets | Same as bundle | Same encryption layer as bundle |
| Scanner bypass HMAC secret | Critical — equivalent to backend scanner trust boundary | Rotated yearly, dual-secret during rotation | Vault, never logged |
| Audit log entries | High — forensic record | 7 years (banking retention) | Append-only Postgres + WORM-replicated to object store |
| KMS data encryption keys (DEKs) | Critical | Per-bundle ephemeral; rotated quarterly | Wrapped by KMS master key (HSM-backed in customer's KMS provider) |

### 2.2 Trust boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  Customer's recording user (workstation, sandboxed Chrome)    │
└──────────────────────────────────────────────────────────────┘
        │ (TLS 1.3 + mTLS, session bound to user IAM)
┌──────────────────────────────────────────────────────────────┐
│  SentinelCore controlplane (MVP: in-cluster API)              │
│  • RBAC enforces who can record/approve/use                   │
│  • Audit logger writes append-only entry per action           │
└──────────────────────────────────────────────────────────────┘
        │ (intra-cluster mTLS, NATS JetStream signed messages)
┌──────────────────────────────────────────────────────────────┐
│  authbroker (sessions in-memory, never written unencrypted)   │
└──────────────────────────────────────────────────────────────┘
        │
┌──────────────────────────────────────────────────────────────┐
│  dast-browser-worker (ephemeral Chrome instances per scan)    │
│  • scope.Enforcer prevents request leakage                    │
│  • InjectCookies hardens to Secure+HttpOnly+SameSite=Strict   │
└──────────────────────────────────────────────────────────────┘
        │ (egress from dedicated allowlistable IPs)
┌──────────────────────────────────────────────────────────────┐
│  Customer's target application                                │
└──────────────────────────────────────────────────────────────┘
```

### 2.3 STRIDE analysis

| # | Threat | Attack vector | Concrete countermeasure | Spec section |
|---|--------|---------------|-------------------------|--------------|
| 1 | **S**poof — fake recording uploaded by malicious insider | Insider with `recorder` role uploads a recording that targets a third-party host disguised as the customer's | Pre-flight host match: replayer aborts if any action's URL host doesn't match the recording's declared `target_host` AND the scan job's allowed scope. Recording metadata signed at capture time, signature verified at replay. | §5.4, §6.2 |
| 2 | **S**poof — sign-up of a forged bundle | Attacker with DB access inserts a bundle row | Bundle integrity HMAC over canonical fields, key sourced from KMS-encrypted secret rotated quarterly. Verify on every load. | §4.3, §7.2 |
| 3 | **T**amper — modify stored recording | Attacker with DB write access modifies action list to add a destructive action | Same HMAC. Plus: replayer compares observed action sequence to recorded sequence; deviations abort the scan. | §4.3, §6.4 |
| 4 | **T**amper — modify session bundle to escalate | Attacker swaps a low-privilege session for an admin session | RBAC binding: bundle records `created_by_user_id` and `session_principal` (decoded from JWT or first response). Replayer rejects scans whose configured target user ≠ session principal. | §6.5 |
| 5 | **R**epudiation — who recorded? | Insider uses recording, denies authorship | Recording metadata includes `created_by_user_id`, `created_by_ip`, `created_by_user_agent`, `created_at`, and an HMAC chain that includes the previous recording's hash (Merkle-style) for tamper detection. | §11.2 |
| 6 | **I**nformation disclosure — bundle leak via logs | Bundle content accidentally logged | Logger redaction layer scrubs `Cookie`, `Authorization`, `Set-Cookie`, `X-CSRF-Token`, and any value present in known credential fields. CI test asserts redaction. | §11.3 |
| 7 | **I**nformation disclosure — bundle leak via memory dump | Process crash dump captures decrypted bundle | Decrypted bundle pinned via `mlock()` (Linux) on the worker; goroutine-local; zeroized on Strategy.Validate failure or scan completion. Crash dumps disabled in production binary. | §4.5 |
| 8 | **I**nformation disclosure — backup leak | Backup tape contains recording in plaintext | Backups use a separate KMS key from active data ("backup-master-key"); restore drill verifies key separation quarterly. | §12.4 |
| 9 | **D**enial of service — recording deletion | Attacker deletes recording before scheduled scan | Soft-delete with 30-day grace window; only `recording_admin` can hard-delete; deletion is itself an audit event with kill-switch ("undo within 24h"). | §10.3, §11.2 |
| 10 | **D**enial — replay loop spam | Attacker triggers replays to exhaust target's rate limits | Replay rate-limited per (recording, target_host) at 1/min; circuit breaker after 3 consecutive failures. | §6.6 |
| 11 | **E**levation — privilege overflow via recording | A recording with admin session is used to scan an endpoint the recorder shouldn't be able to test | Per-recording ACL list of (project_id, scope_id) tuples; replayer rejects out-of-list scan jobs. Reviewer approval (§10) required before the recording is usable. | §10.2 |
| 12 | **E**levation — bypass token forgery | Attacker forges a scanner bypass HMAC | Token derivation includes scan_job_id (UUID, opaque to attacker) and a 5-minute timestamp window; HMAC key per-customer, rotated yearly with dual-key support during transition. Backend SDK rejects tokens older than 5 min. | §9.3 |

### 2.4 Compliance control mapping

| Control | Requirement | This spec's implementation | Section |
|---------|-------------|----------------------------|---------|
| **BDDK §10.5** Erişim ve yetkilendirme | Segregation of duties on critical operations | Recorder ≠ Approver ≠ Operator (4-eyes for first use) | §10 |
| **BDDK §11.4** Kayıt yönetimi | Immutable audit logging of access to sensitive data | Append-only Postgres + WORM mirror | §11 |
| **KVKK Md. 12** Veri güvenliği | Encryption at rest and in transit; minimization | AES-256-GCM at rest, TLS 1.3 in transit, retention TTL | §4, §7 |
| **PCI-DSS 3.5** Cryptographic key management | Key rotation, key separation, restricted access | KMS envelope encryption, quarterly rotation, dual-key transition | §4 |
| **PCI-DSS 8.6** Authentication mechanisms | MFA on administrative access; periodic re-auth | Recording session bound to user IAM; reviewer step requires fresh re-auth (≤15 min old) | §10.4 |
| **PCI-DSS 10.2** Audit trails | Log all access to cardholder data; tamper-evident | All bundle access audit-logged; HMAC chain | §11 |
| **ISO 27001 A.9.4.5** Access control to source code / config | Bundle ACL enforces project/scope binding | Per-recording ACL | §10.2 |
| **ISO 27001 A.10.1.2** Key management | Documented KMS lifecycle | KMS hierarchy + rotation runbook | §4, §12.3 |
| **SOC 2 CC7.2** Detection of security incidents | SIEM-integrated alerting | CEF/syslog export, alert rules | §11.4 |
| **NIST 800-53 IA-5** Authenticator management | Authenticators encrypted, rotated | Bundle TTL, scanner bypass secret rotation | §7.3, §9.4 |
| **NIST 800-53 AC-6** Least privilege | Per-resource ACL, role separation | RBAC + bundle ACL | §10 |

---

## 3. Component architecture

### 3.1 Components

| # | Component | Responsibility | Code location |
|---|-----------|----------------|---------------|
| 3.1.1 | **Recording UI (Web)** | Customer admin-portal page that initiates a recording session, displays recording status, and renders an approval queue for reviewers | `web/src/features/dast/recording/` (new) |
| 3.1.2 | **Recording UI (CLI)** | `sentinelcore dast record` command that opens a sandboxed Chrome locally, records the user's actions, and uploads a signed bundle | `cmd/cli/dast/record.go` (new) |
| 3.1.3 | **Recording Orchestrator** | Server-side service that sandboxes Chrome (via existing `internal/browser/`), captures action stream and final session, signs bundle, persists to storage | `internal/authbroker/recording/` (new sub-package) |
| 3.1.4 | **Bundle Storage** | Database row (`dast_auth_bundles`) + object store (encrypted blob); CRUD with audit log integration | `internal/authbroker/bundles/` (new sub-package) |
| 3.1.5 | **SessionImportStrategy** | Authbroker strategy that consumes a bundle uploaded directly (no recording) | `internal/authbroker/strategies.go` (extend) |
| 3.1.6 | **RecordedLoginStrategy** | Authbroker strategy that loads a bundle, evaluates whether the recording is automatable, replays via dast-browser-worker (auto-mode) or returns the captured session (one-shot mode) | `internal/authbroker/strategies.go` (extend) |
| 3.1.7 | **Replay Engine** | Sandboxed Chrome session launched for refresh; runs the recorded action list with anomaly detection and scope enforcement | `internal/authbroker/recording/replayer.go` (new) |
| 3.1.8 | **Scanner Bypass Token Issuer** | Computes HMAC-signed token per scan job; injects header into all DAST requests | `internal/dast/scanner_bypass.go` (new) |
| 3.1.9 | **Customer SDK middlewares** | Reference implementations for Go / Java / Python / .NET; documented contract for customer-side CAPTCHA skipping | `customer-sdks/` (new top-level dir, separate Go modules) |
| 3.1.10 | **KMS Adapter** | Pluggable interface for AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault Transit; envelope encryption for bundles | `internal/kms/` (new) |
| 3.1.11 | **Audit Log Writer** | Immutable, signed audit entries; CEF/syslog SIEM export | `internal/audit/` (new — separate from existing `audit-service` if any) |
| 3.1.12 | **RBAC & Approval Workflow** | New roles, per-recording ACL, 4-eyes approval flow, kill switch | `internal/authz/` (extend existing) |

### 3.2 Data flow — recording

```
1. Recorder user authenticates to controlplane (existing IAM, fresh ≤15 min).
2. Recorder POSTs /api/v1/dast/recordings { target_host, project_id, intent }.
   Controlplane returns recording_session_id + ephemeral upload token.
3. Recording UI/CLI launches sandboxed Chrome (ephemeral profile, no extensions,
   network filter only allows target_host + recorder's auth IdP).
4. User logs in normally — solves CAPTCHA, completes any MFA.
5. Recorder stops recording. Tool finalizes:
   a. Action list = ordered list of (timestamp, action_type, selector, value_hash)
      where credentials are stored as SHA-256 hashes only; the literal cred is
      pulled from Vault at replay time.
   b. Final session = cookies + Authorization headers + relevant localStorage.
   c. Metadata = target_host, target_principal (if derivable from JWT/cookie),
      created_by, created_at, browser fingerprint (user-agent canonical form),
      recording duration, hash of last response body.
6. Tool computes content HMAC and uploads via mTLS to controlplane.
7. Controlplane:
   a. Verifies upload token, recorder's IAM session.
   b. Runs server-side validation (Section 5.4).
   c. KMS-encrypts bundle, persists to dast_auth_bundles + object store.
   d. Writes audit entry "recording.created".
8. Bundle enters "pending_review" state. Notification sent to reviewers.
```

### 3.3 Data flow — approval

```
1. Reviewer (separate IAM identity from recorder) opens approval queue.
2. Reviews metadata: target_host, action count, action diff vs prior recording
   (if refresh), screenshots of key transitions (cropped, no PII).
3. Approves or rejects. If approved, sets:
   a. ACL: list of (project_id, scope_id) where bundle is usable.
   b. TTL: max active duration (default 24h, hard cap 7 days).
   c. Refresh policy: automatable / one-shot.
4. Audit entry "recording.approved" or "recording.rejected".
5. Bundle enters "approved" state and is now usable by scan jobs in ACL.
```

### 3.4 Data flow — scan with replay

```
1. Scan operator launches scan referencing (project_id, target_url, recording_id).
2. Controlplane resolves the bundle:
   a. Loads row, decrypts via KMS.
   b. Verifies content HMAC.
   c. Checks ACL (project_id, scope_id ∈ bundle.acl).
   d. Checks not expired, not revoked, not soft-deleted.
   e. Audit entry "recording.access".
3. authbroker.CreateSession is called:
   a. Strategy = RecordedLoginStrategy.
   b. If bundle is one-shot OR auto-replay TTL still valid → use captured session.
   c. If bundle is automatable AND captured session expired → launch replay engine.
4. Replay engine (when needed):
   a. Spawns ephemeral sandboxed Chrome.
   b. Runs each action in order with pre-flight checks (Section 6).
   c. On success, returns fresh session. On failure, marks bundle as needing re-record.
5. dast-browser-worker / dast-worker injects session cookies + headers + bypass
   token into scan requests, scoped via scope.Enforcer.
6. Audit entry "recording.used" (every scan).
```

### 3.5 Data flow — refresh fail

```
1. Scheduled refresh attempt fails (replay action mismatch, target host returns
   CAPTCHA on a previously CAPTCHA-free page, etc.).
2. Bundle marked "refresh_required". Active scans complete with last-known
   session if not yet expired; new scans block.
3. Audit entry "recording.refresh_failed" with diagnostic details.
4. Notification sent to original recorder + recording_admin role.
5. Recorder must re-record.
```

---

## 4. Cryptographic boundaries

### 4.1 Key hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│  Customer KMS Master Key                                    │
│  • HSM-backed (FIPS 140-2 Level 3 minimum)                  │
│  • Customer-managed (BYOK supported)                        │
│  • Rotation: customer policy, recommended yearly            │
└─────────────────────────────────────────────────────────────┘
        │ wraps
┌─────────────────────────────────────────────────────────────┐
│  Per-bundle DEK (Data Encryption Key)                       │
│  • AES-256, generated per bundle at recording time          │
│  • Wrapped DEK stored alongside bundle row                  │
│  • Rotation: re-wrap quarterly without re-encrypting blob   │
│    (KMS rewrap operation; key version bumped)               │
└─────────────────────────────────────────────────────────────┘
        │ encrypts
┌─────────────────────────────────────────────────────────────┐
│  Bundle blob (action list + session)                        │
│  • AES-256-GCM, IV per encrypt operation                    │
│  • Authenticated additional data (AAD): bundle_id ‖ version │
└─────────────────────────────────────────────────────────────┘

Separately:
┌─────────────────────────────────────────────────────────────┐
│  Bundle integrity HMAC                                      │
│  • HMAC-SHA-256 over canonical metadata + ciphertext        │
│  • Key derived from a separate KMS path ("bundle-hmac-key") │
│  • Rotated quarterly                                        │
└─────────────────────────────────────────────────────────────┘

Separately:
┌─────────────────────────────────────────────────────────────┐
│  Per-customer Scanner Bypass Secret                         │
│  • 256-bit, generated per customer onboarding               │
│  • Stored in Vault, retrieved by DAST worker per scan       │
│  • Rotation: yearly, dual-secret window of 30 days          │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Cryptographic algorithm choices

| Use case | Algorithm | Rationale |
|----------|-----------|-----------|
| Bundle encryption | AES-256-GCM | NIST-approved AEAD; FIPS 140-2 compatible; widely deployed in cloud KMS APIs |
| Bundle integrity | HMAC-SHA-256 | FIPS-approved MAC; complements GCM authentication for non-content metadata |
| Scanner bypass token | HMAC-SHA-256 | Same family; verifiable in customer SDKs without ASN.1 parsing |
| TLS | TLS 1.3 only | Customer firewalls already deployed; older TLS rejected with explicit error |
| Cookie encryption (in transit between worker and target) | Customer's TLS | We do not double-encrypt — that would mask issues we should detect |
| Audit log signing | Ed25519 | Compact, deterministic, no nonce reuse risk, NIST-approved (FIPS 186-5) |

### 4.3 Bundle encryption in detail

```
plaintext = canonicalize(action_list || session)  // JSON, deterministic field order
dek       = KMS.GenerateDataKey()  // returns (plaintext_dek, wrapped_dek)
iv        = csprng(12)             // GCM nonce
aad       = bundle_id || schema_version
ciphertext, tag = AES-256-GCM(dek, iv, plaintext, aad)
wipe(dek)                          // zeroize plaintext DEK from memory

stored:
  bundle_id, schema_version, customer_id, project_id, ...metadata...,
  iv, ciphertext, tag, wrapped_dek, kms_key_id, kms_key_version

hmac_input = canonical(metadata) || iv || ciphertext || tag || wrapped_dek
hmac_key   = KMS.GetHMACKey()   // separate KMS path
integrity_hmac = HMAC-SHA-256(hmac_key, hmac_input)
stored: integrity_hmac

Decryption:
  verify integrity_hmac first (constant-time compare)
  unwrap wrapped_dek via KMS
  AES-256-GCM decrypt with iv, aad
  zeroize plaintext_dek immediately on completion or error
```

### 4.4 KMS adapter contract

```go
// internal/kms/kms.go (new)
type Provider interface {
    // GenerateDataKey returns a fresh AES-256 key wrapped by the provider's
    // master key. Returns (plaintext, wrapped, key_version).
    GenerateDataKey(ctx context.Context, purpose string) (DataKey, error)

    // Decrypt unwraps a previously-wrapped DEK. Returns plaintext DEK; caller
    // must zeroize after use.
    Decrypt(ctx context.Context, wrapped []byte, kekVersion string) ([]byte, error)

    // Sign / Verify for HMAC and signature operations (key never leaves KMS).
    HMAC(ctx context.Context, keyPath string, msg []byte) ([]byte, error)
    HMACVerify(ctx context.Context, keyPath string, msg, mac []byte) (bool, error)
}

type DataKey struct {
    Plaintext   []byte // 32 bytes; caller MUST call Zeroize() when done
    Wrapped     []byte // opaque to caller; provider-specific format
    KeyVersion  string
}

func (k *DataKey) Zeroize() { for i := range k.Plaintext { k.Plaintext[i] = 0 } }
```

Implementations land for: AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault Transit, and a `LocalDev` provider (file-backed; rejected in production by environment check).

### 4.5 Memory hygiene

- Decrypted bundles are pinned via `unix.Mlock` (Linux) on the worker process to prevent paging to swap.
- Goroutines that handle decrypted material are short-lived; bundles are decrypted on demand per scan, never cached at the broker level.
- Crash dumps are disabled in production binaries via `syscall.Setrlimit(RLIMIT_CORE, 0)`.
- Linter rule (custom golangci-lint) flags any path that copies a `Session.Cookies[i].Value` into a logger field.

### 4.6 Key rotation runbook references

Documented in §12.3; runbook lives at `docs/runbooks/dast-key-rotation.md` (separate document).

---

## 5. Recording subsystem

### 5.1 Sandboxing the recording browser

The recording user runs Chrome on their workstation (CLI flow) or in a controlled environment (Web flow uses a dedicated recording orchestrator pod). In both cases:

| Control | Implementation |
|---------|----------------|
| Ephemeral profile | New `--user-data-dir` per recording session, deleted after upload |
| No extensions | Chrome launched with `--disable-extensions` + extension policy enforcement |
| Network filter | Workstation: tool spawns a local proxy (mitmproxy-style) that allows only target host + customer IdP. Server-side flow: egress firewall enforces the same. |
| Disable autofill | `--disable-features=Autofill,FillingAcrossAffiliations` |
| Disable telemetry | `--disable-features=ChromeCleanup,NetworkService,SafeBrowsingEnhancedProtection` |
| No cache reuse | New profile means cold start; cookies from prior recording sessions cannot leak |
| Screen recording disabled | OS-level: tool hints to OS to suppress remote-desktop frame capture during recording (best-effort; documented as user responsibility) |

### 5.2 Action capture

The recorder uses chromedp's existing event listeners (we already use chromedp throughout `internal/browser/`):

| Captured | Source | Stored as |
|----------|--------|-----------|
| Navigate | `Page.frameNavigated` | `{type: "navigate", url, timestamp}` |
| Form fill | `Input.dispatchKeyEvent` listener + DOM mutation observer | `{type: "fill", selector, value_hash}` — literal value pulled from Vault at replay |
| Click | `Input.dispatchMouseEvent` + DOM event listener | `{type: "click", selector, modifiers}` |
| Wait condition | Inferred from time between actions | `{type: "wait_for_load", min_ms, max_ms}` |
| CAPTCHA detected | Heuristic: img/iframe with `recaptcha`/`hcaptcha`/`turnstile` selectors | `{type: "captcha_marker", solver_required: true}` — replayer treats this as a one-shot boundary |
| Final session | `Network.getAllCookies` + `localStorage` snapshot + last response headers | `{cookies, local_storage, response_headers}` |

Selectors are stored using a stability-ranked strategy: prefer `data-testid`, then `id`, then accessibility label, then CSS path. The recorder records all four where available; replayer tries them in order until one matches.

### 5.3 Credentials are never literals in the recording

Crucial: **the recording does not store passwords, tokens, or any value that should not be stored.** When the user fills a form field that the tool detects as sensitive (input type=password, autocomplete=current-password, name~=password|token|secret), the tool:

1. Hashes the value with SHA-256 + per-recording salt.
2. Stores `{type: "fill_from_vault", selector, vault_key, value_hash}` in the action.
3. Prompts the recording user: "This field looks sensitive. Save it under Vault key `<auto-suggested>` for replay?"
4. On confirmation, the literal value is written to Vault under a per-recording path; never stored alongside the recording.

At replay time, the worker fetches the Vault value with a per-replay token, fills the field, and zeroizes. The recording itself is therefore not enough to log into the target — it requires Vault access scoped to the recording.

### 5.4 Server-side validation

When the recording reaches the controlplane, the orchestrator validates:

| Check | Action on failure |
|-------|-------------------|
| Schema version supported | Reject with explicit error |
| All action targets within `target_host` (no exfil) | Reject |
| Action count ≤ 200 (sanity bound) | Reject (suggests recording is non-canonical) |
| Recording duration ≤ 10 min | Reject |
| `target_host` matches a registered project in customer's tenancy | Reject |
| No raw credential strings in action values | Reject (defensive — the recorder should have caught) |
| Captured session present (cookies non-empty OR auth header present) | Reject (recording produced no usable session) |
| Final response status ∈ {200, 302} (heuristic for "logged in") | Warn, allow — reviewer must approve |
| Bundle size ≤ 1 MiB compressed | Reject |
| HMAC computed by recorder verifies | Reject |

Validation results are part of the audit entry and surface in the reviewer UI.

### 5.5 Recorder output bundle format

JSON, canonicalized via [JCS RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) for deterministic HMAC:

```json
{
  "schema_version": 1,
  "bundle_id": "uuid",
  "customer_id": "uuid",
  "project_id": "uuid",
  "target_host": "app.bank.tld",
  "target_principal": "user-id-decoded-from-jwt-or-empty",
  "created_by_user_id": "uuid",
  "created_by_ip": "ipv4-or-v6",
  "created_by_user_agent": "Chrome/126 ...",
  "created_at": "RFC3339-ns",
  "browser_fingerprint": "sha256-hex",
  "recording_duration_ms": 47200,
  "actions": [...],
  "captured_session": {
    "cookies": [...],
    "local_storage": [...],
    "response_headers": {...}
  },
  "captcha_in_flow": true,
  "automatable_refresh": false,
  "ttl_seconds": 86400,
  "schema_hash": "sha256-of-this-document-without-this-field"
}
```

Fields not yet known (e.g. `target_principal` if extraction fails) are explicit empty strings, not omitted.

### 5.6 Browser fingerprint

`browser_fingerprint = SHA-256(canonical(user_agent ‖ accept_language ‖ viewport ‖ os))`. Used at replay time to flag drift if the customer regenerates a recording with a different browser configuration; replay engine warns but does not block (browser version drift is normal during refresh cadence).

---

## 6. Replay subsystem

### 6.1 Modes

| Mode | When | Behavior |
|------|------|----------|
| **One-shot** | `captcha_in_flow == true` OR `automatable_refresh == false` | Replay engine is NOT invoked. The captured session is used directly until TTL expires; on expiry, customer must re-record. |
| **Automatable** | `captcha_in_flow == false` AND `automatable_refresh == true` | Replay engine launches Chrome, runs action list, captures fresh session. |

This is a customer-driven flag set during recording approval (Section 10), with the recorder's heuristic guess as default.

### 6.2 Pre-flight checks (executed before replay starts)

1. **Bundle integrity** — verify HMAC; if fail, abort + audit "recording.integrity_failed".
2. **Bundle ACL** — scan job's (project_id, scope_id) ∈ bundle.acl; if not, abort + audit "recording.acl_violation" (this is a security event).
3. **Bundle status** — must be "approved", not "revoked", not "refresh_required", not soft-deleted.
4. **TTL** — recording_age < ttl_seconds.
5. **Target host match** — every action's URL host == bundle.target_host (exact, or in customer-declared subdomain set).
6. **Action count not changed** — replay loads the same N actions originally recorded.
7. **Replay rate limit** — last 5 replay attempts not all failed; circuit breaker if so.

### 6.3 Action execution

The replayer runs each action with bounded waits and per-action assertions:

```
for i, action := range bundle.actions:
    expectStartURL(action.expected_url_pattern)  // continues if matches
    switch action.type:
        navigate:    chromedp.Navigate(action.url) with 15s timeout
        fill:        chromedp.Value(action.selector_chain, fetchVaultValue(action.vault_key))
        click:       chromedp.Click(action.selector_chain)
        wait:        chromedp.Sleep(action.min_ms..action.max_ms)
        captcha:     ABORT — should not be reached in automatable mode
    assertResultMatches(action.expected_post_state_hash)
    if duration > 3 * recorded_duration: abort with "anomaly: slow"
    if URL host left target_host: abort with "scope violation"

After last action:
    cookies := chromedp.Network.getAllCookies()
    storage := evaluateLocalStorage()
    headers := lastResponseHeaders()
    return Session{cookies, headers, storage}
```

### 6.4 Post-state assertion

Each action has an `expected_post_state_hash` recorded at capture time:

```
expected_post_state_hash = SHA-256(url_path || dom_skeleton_hash)

dom_skeleton_hash = SHA-256(canonical(visible_form_selectors || h1/h2 text || nav landmarks))
```

If the post-state hash diverges, the target's UI has changed structurally. Replay aborts with `recording.refresh_required` audit entry; the recording is flagged for re-capture rather than retried. Tolerance is intentional: minor text changes (button label A/B test) don't invalidate the hash because the skeleton doesn't include button text.

### 6.5 Principal binding

If the recording captured a JWT or known session-principal cookie, `bundle.target_principal` is populated. The scan job config also declares which principal it intends to test. At replay time:

```
if bundle.target_principal != "" and scan.expected_principal != "":
    require bundle.target_principal == scan.expected_principal
```

This prevents "use a low-priv recording to scan an admin endpoint" mismatches. If unset on either side, no binding (with audit warning).

### 6.6 Replay rate limit & circuit breaker

Per `(bundle_id, target_host)`:
- Max 1 replay per 60 seconds.
- After 3 consecutive replay failures: circuit opens; bundle marked `refresh_required`.
- Manual reset only by `recording_admin`.

### 6.7 Kill switch

Customer admin can revoke any bundle instantly via UI/API:

```
POST /api/v1/dast/recordings/{id}/revoke
```

Effects:
1. Bundle status → `revoked`.
2. All running replays observe revocation within ≤2 seconds (cooperative cancel via context).
3. Active scan jobs using the bundle are paused; operator notified.
4. Audit entry "recording.revoked".
5. Wrapped DEK is **destroyed** (KMS-side; bundle becomes permanently unrecoverable — chosen design tradeoff).

---

## 7. Storage & retention

### 7.1 Schema

```sql
CREATE TABLE dast_auth_bundles (
    id                  UUID PRIMARY KEY,
    customer_id         UUID NOT NULL REFERENCES customers(id),
    project_id          UUID NOT NULL REFERENCES projects(id),
    target_host         TEXT NOT NULL,
    target_principal    TEXT,
    type                TEXT NOT NULL CHECK (type IN ('session_import','recorded_login')),
    status              TEXT NOT NULL CHECK (status IN ('pending_review','approved','revoked','refresh_required','expired','soft_deleted')),

    -- Cryptographic envelope
    iv                  BYTEA NOT NULL,
    ciphertext_ref      TEXT NOT NULL,              -- object store path or inline if small
    aead_tag            BYTEA NOT NULL,
    wrapped_dek         BYTEA NOT NULL,
    kms_key_id          TEXT NOT NULL,
    kms_key_version     TEXT NOT NULL,
    integrity_hmac      BYTEA NOT NULL,
    schema_version      INT NOT NULL,

    -- Lifecycle
    created_by_user_id  UUID NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by_user_id UUID,
    approved_at         TIMESTAMPTZ,
    last_used_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    soft_deleted_at     TIMESTAMPTZ,
    hard_delete_after   TIMESTAMPTZ,

    -- Replay configuration
    captcha_in_flow     BOOLEAN NOT NULL,
    automatable_refresh BOOLEAN NOT NULL,
    ttl_seconds         INT NOT NULL,
    refresh_count       INT NOT NULL DEFAULT 0,
    consecutive_failures INT NOT NULL DEFAULT 0,

    -- Audit metadata (denormalized for fast queries)
    use_count           BIGINT NOT NULL DEFAULT 0,
    metadata_jsonb      JSONB NOT NULL              -- non-sensitive: target_host, action_count, etc.
);

CREATE INDEX dast_auth_bundles_project_status ON dast_auth_bundles(project_id, status)
    WHERE status IN ('approved', 'pending_review');
CREATE INDEX dast_auth_bundles_expiry ON dast_auth_bundles(expires_at)
    WHERE status = 'approved';

-- ACL: which (project_id, scope_id) tuples can use this bundle
CREATE TABLE dast_auth_bundle_acls (
    bundle_id  UUID NOT NULL REFERENCES dast_auth_bundles(id) ON DELETE CASCADE,
    project_id UUID NOT NULL,
    scope_id   UUID,                                 -- NULL = whole project
    PRIMARY KEY (bundle_id, project_id, scope_id)
);
```

### 7.2 Object store layout

```
s3://sentinelcore-{customer_id}-bundles/
    bundles/{yyyy}/{mm}/{dd}/{bundle_id}.bin    -- AES-256-GCM ciphertext
    bundles-archive/{yyyy}/{bundle_id}.bin       -- after soft-delete grace
```

SSE-KMS at the bucket level (defense-in-depth — bundle is already encrypted client-side).

### 7.3 Retention policy

| Status | Lifetime | Action |
|--------|----------|--------|
| `pending_review` | 7 days | Auto-expire if not approved |
| `approved` | TTL bounded to `expires_at` (default 24h, customer-configurable up to 7 days) | On expiry: status → `expired`; encrypted blob retained 30 days for audit; then hard-delete |
| `refresh_required` | 7 days | Same as expired |
| `revoked` | Immediate DEK destroy; row + ciphertext retained 7 years for audit (decryption impossible) | KVKK / BDDK retention |
| `soft_deleted` | 30 days grace | After grace: hard-delete row + blob + DEK |
| `expired` | 30 days | Then hard-delete |

### 7.4 GDPR / KVKK right to erasure

A customer can request deletion of a recording at any time:
1. API call → status moves to `soft_deleted`.
2. After 30-day grace window (or immediate if customer waives grace), row + blob + DEK destroyed.
3. Audit log entry retained — the audit log itself is anonymized for the deleted bundle (target_principal stripped), but the structural record (who, when, action) is retained per banking audit requirements.

The audit log's retained metadata never includes credentials, cookies, or PII; only structural fields (bundle_id, customer_id, project_id, action verb).

---

## 8. Auth strategies

### 8.1 SessionImportStrategy

```go
// internal/authbroker/strategies.go (extension)
type SessionImportStrategy struct {
    bundles BundleStore
    audit   audit.Writer
}

func (s *SessionImportStrategy) Name() string { return "session_import" }

func (s *SessionImportStrategy) Authenticate(ctx context.Context, cfg AuthConfig) (*Session, error) {
    bundleID := cfg.Credentials["bundle_id"]
    bundle, err := s.bundles.LoadAndDecrypt(ctx, bundleID, cfg.CustomerID)
    if err != nil { return nil, err }

    if err := bundle.VerifyACL(cfg.ProjectID, cfg.ScopeID); err != nil { return nil, err }
    if err := bundle.VerifyNotExpired(); err != nil { return nil, err }
    if bundle.Type != "session_import" { return nil, ErrWrongStrategy }

    s.audit.Write(ctx, audit.Event{Type: "recording.access", BundleID: bundleID, ...})

    return &Session{
        Cookies:   bundle.CapturedCookies(),
        Headers:   bundle.CapturedHeaders(),
        ExpiresAt: bundle.ExpiresAt,
    }, nil
}

func (s *SessionImportStrategy) Refresh(ctx context.Context, _ *Session, cfg AuthConfig) (*Session, error) {
    return nil, ErrManualRefreshRequired
}

func (s *SessionImportStrategy) Validate(_ context.Context, session *Session) (bool, error) {
    return !session.IsExpired() && len(session.Cookies) > 0, nil
}
```

### 8.2 RecordedLoginStrategy

```go
type RecordedLoginStrategy struct {
    bundles  BundleStore
    audit    audit.Writer
    replayer replayer.Engine
}

func (s *RecordedLoginStrategy) Authenticate(ctx context.Context, cfg AuthConfig) (*Session, error) {
    bundleID := cfg.Credentials["bundle_id"]
    bundle, err := s.bundles.LoadAndDecrypt(ctx, bundleID, cfg.CustomerID)
    if err != nil { return nil, err }
    if err := bundle.VerifyACL(cfg.ProjectID, cfg.ScopeID); err != nil { return nil, err }
    if bundle.Type != "recorded_login" { return nil, ErrWrongStrategy }

    s.audit.Write(ctx, audit.Event{Type: "recording.access", BundleID: bundleID})

    if !bundle.AutomatableRefresh || !bundle.HasFreshCapturedSession() {
        // One-shot: use captured session as-is until expiry.
        return bundle.CapturedSession(), nil
    }

    return s.Refresh(ctx, nil, cfg)
}

func (s *RecordedLoginStrategy) Refresh(ctx context.Context, _ *Session, cfg AuthConfig) (*Session, error) {
    bundle, _ := s.bundles.LoadAndDecrypt(ctx, cfg.Credentials["bundle_id"], cfg.CustomerID)
    if !bundle.AutomatableRefresh {
        return nil, ErrManualRefreshRequired
    }

    session, err := s.replayer.Replay(ctx, bundle)
    if err != nil {
        s.bundles.MarkRefreshFailure(ctx, bundle.ID, err)
        return nil, err
    }
    s.bundles.RecordSuccessfulRefresh(ctx, bundle.ID, session)
    return session, nil
}
```

### 8.3 Bundle store contract

```go
type BundleStore interface {
    LoadAndDecrypt(ctx context.Context, id, customerID string) (*Bundle, error)
    SaveEncrypted(ctx context.Context, b *Bundle) error
    UpdateStatus(ctx context.Context, id string, status string) error
    Revoke(ctx context.Context, id string, reason string) error
    SoftDelete(ctx context.Context, id string) error
    MarkRefreshFailure(ctx context.Context, id string, err error) error
    RecordSuccessfulRefresh(ctx context.Context, id string, fresh *Session) error
}
```

Implementation `bundles.PostgresStore` wraps Postgres + S3 + KMS + audit.

---

## 9. Scanner bypass token (Approach C)

### 9.1 Token format

```
Header: X-Sentinelcore-Scanner-Token: v1.{timestamp}.{scan_job_id}.{nonce}.{hmac}

where:
  v1 = format version
  timestamp = unix seconds (10 chars)
  scan_job_id = UUID (36 chars)
  nonce = 16-byte hex (32 chars) — prevents replay even within timestamp window
  hmac = HMAC-SHA-256(customer_secret, "v1|timestamp|scan_job_id|nonce|target_host")
         encoded base64url no-pad (43 chars)
```

Total header value: ~130 chars. Within standard HTTP header size limits.

### 9.2 Customer back-end verification (reference middleware)

The customer's staging/test environment includes a middleware that:

```go
// customer-sdks/go/sentinelcore_scanner_bypass.go
func ScannerBypassMiddleware(secret []byte, allowedScopes []string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            tok := r.Header.Get("X-Sentinelcore-Scanner-Token")
            if tok == "" {
                next.ServeHTTP(w, r)
                return
            }
            v, err := VerifyScannerBypassToken(tok, secret, r.Host)
            if err != nil {
                next.ServeHTTP(w, r)
                return
            }
            if !slices.Contains(allowedScopes, v.ScanJobID) && len(allowedScopes) > 0 {
                next.ServeHTTP(w, r)
                return
            }
            // Skip CAPTCHA / signal trusted scanner downstream
            ctx := context.WithValue(r.Context(), trustedScannerCtxKey{}, v)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

Reference implementations ship for Go, Java (Spring Boot filter), Python (Flask + Django), .NET (ASP.NET middleware), Node (Express middleware).

**Critical security property:** the customer back-end MUST be configured with the secret obtained securely (Vault / AWS Secrets Manager / Azure Key Vault). Never check secrets into the customer's source repo.

### 9.3 Anti-replay protections

| Attack | Defense |
|--------|---------|
| Token captured + replayed | 5-minute timestamp window enforced server-side |
| Token captured + replayed within window | Per-customer nonce cache (Redis or local LRU) — each nonce accepted at most once per validity window |
| Token captured + replayed against different host | `target_host` is part of HMAC input — token is host-bound |
| Token captured + replayed against different scan | scan_job_id is part of HMAC input — token is scan-bound |
| Customer secret leak | Yearly rotation with 30-day dual-secret window; immediate revoke endpoint |
| HMAC algorithm downgrade attack | Version prefix `v1` validates algorithm; future `v2` introduces new construction without retro-compatible verification |

### 9.4 Secret lifecycle

- **Generation:** customer onboarding ceremony — secret generated server-side, displayed once to customer admin, stored in Vault. Customer copies to their secrets manager out-of-band.
- **Rotation:** scheduled yearly. New secret generated 30 days before old expires; both accepted during window. Audit entries `bypass_secret.rotation_started`, `bypass_secret.rotation_completed`.
- **Compromise response:** customer admin clicks "Rotate Now" → new secret generated, old secret invalidated immediately, all in-flight scans abort with `bypass_secret_revoked`. Customer pushes new secret to their backend ASAP.

### 9.5 Backend integration patterns (documented for customers)

| Pattern | Use case | Tradeoff |
|---------|----------|----------|
| **Skip CAPTCHA challenge** | Login / signup endpoints | Customer must ensure middleware is staging-only, not production |
| **Bypass rate limit** | Brute-force-protected endpoints under scan | Same; but useful for fuzzing |
| **Auto-MFA-pass** | MFA-protected endpoints | Customer accepts that MFA is bypassed in scanner-flagged requests; their staging should have isolated test users |
| **Verbose error mode** | Endpoints that mask 500s in production | Returns structured error for scanner; helps DAST distinguish 500 from intentional 200-with-error-body |

Each pattern has documentation page with code examples and risk warnings.

---

## 10. RBAC & approval workflow

### 10.1 Roles (extension of existing IAM)

| Role | Permissions (relevant to DAST auth) |
|------|-------------------------------------|
| `dast.recorder` | Create recording session; upload bundle; view own pending recordings |
| `dast.recording_reviewer` | View pending recordings (organization-wide); approve/reject; cannot create or use |
| `dast.scan_operator` | Use approved recordings in scans they own |
| `dast.recording_admin` | Hard-delete; revoke; force-rotate scanner bypass secret; view all bundles' metadata (never decrypted content) |
| `dast.audit_viewer` | Read-only access to audit log |

### 10.2 Per-bundle ACL

Independent of role grants:

```
dast_auth_bundle_acls(bundle_id, project_id, scope_id)
```

A scan job is permitted to use a bundle iff there exists an ACL row `(bundle.id, scan.project_id, NULL or scan.scope_id)`. ACL is set during approval (Section 10.4) and editable only by `dast.recording_admin` post-approval.

### 10.3 Soft-delete vs hard-delete

| Operation | Required role | Audit entry | Reversibility |
|-----------|---------------|-------------|---------------|
| Soft delete | `dast.recorder` (own) or `dast.recording_admin` | `recording.soft_deleted` | Reversible within 30-day grace by `dast.recording_admin` |
| Hard delete | `dast.recording_admin` only | `recording.hard_deleted` | Irreversible; KMS DEK destroyed |
| Revoke (active session) | `dast.recording_admin` | `recording.revoked` | Irreversible (DEK destroyed) |

### 10.4 Approval workflow (4-eyes)

```
1. Recorder uploads bundle → status `pending_review`.
2. Reviewer (different IAM user from recorder) opens bundle in approval UI.
3. Approval requires the reviewer to:
   a. Re-authenticate (≤15 min old session, MFA required).
   b. View metadata, screenshots of action transitions, action diff vs prior recording.
   c. Set ACL (which projects/scopes), TTL, refresh policy.
   d. Confirm with attestation: "I have verified the recording targets only systems
      authorized for testing under <named scope>".
4. On approve:
   a. Bundle status → `approved`.
   b. Audit entry `recording.approved` with reviewer's user_id, IP, timestamp,
      attestation text.
   c. Bundle becomes usable by scan_operators in ACL.
5. Re-approval required after:
   a. Bundle is refreshed via re-record (treated as new bundle linked via
      `predecessor_bundle_id`).
   b. ACL change attempted (any modification re-enters approval queue).
```

The recorder cannot approve their own recording. Postgres trigger enforces `recorder.user_id != reviewer.user_id`.

### 10.5 Reviewer approval queue UI

Web UI shows for each pending recording:
- Target host and resolved IP (with WHOIS hint, "this host is in your declared asset list" badge).
- Recording duration, action count, whether CAPTCHA was detected, predicted automatable status.
- Sanitized action sequence (URLs visible, values redacted).
- Side-by-side diff against the most recent prior approved bundle for the same `(project_id, target_host)` pair, if any.
- 4 cropped screenshots from the recording (at 25/50/75/100% progress) with PII masking via simple input-field redaction overlay.
- Approve / Reject / Request Re-record buttons.

---

## 11. Audit & observability

### 11.1 Event taxonomy

All events conform to a versioned schema:

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "event_type": "recording.created",
  "event_timestamp": "RFC3339-ns",
  "actor_user_id": "uuid",
  "actor_ip": "ip",
  "actor_user_agent": "...",
  "actor_session_id": "uuid",
  "target_resource_type": "dast_auth_bundle",
  "target_resource_id": "uuid",
  "customer_id": "uuid",
  "project_id": "uuid",
  "outcome": "success | failure | partial",
  "details": { ... event-specific, never includes credentials ... },
  "previous_event_hash": "sha256-of-previous-event-canonical",
  "event_signature": "ed25519-signature"
}
```

Event types (non-exhaustive):

```
recording.created              recording.access
recording.upload_validated     recording.acl_violation
recording.uploaded             recording.revoked
recording.pending_review       recording.refresh_started
recording.approved             recording.refresh_succeeded
recording.rejected             recording.refresh_failed
recording.soft_deleted         recording.expired
recording.hard_deleted         recording.integrity_failed
recording.used                 recording.kill_switch_invoked

bypass_secret.generated        bypass_secret.rotation_started
bypass_secret.rotation_completed  bypass_secret.revoked

bundle_acl.added               bundle_acl.removed
```

### 11.2 Tamper evidence

Append-only Postgres table with computed `previous_event_hash` chain — any in-place mutation breaks the chain.

```sql
CREATE TABLE audit_events (
    event_id              UUID PRIMARY KEY,
    schema_version        INT NOT NULL,
    event_type            TEXT NOT NULL,
    event_timestamp       TIMESTAMPTZ NOT NULL,
    actor_user_id         UUID,
    actor_ip              INET,
    target_resource_type  TEXT,
    target_resource_id    UUID,
    customer_id           UUID NOT NULL,
    outcome               TEXT NOT NULL,
    details_jsonb         JSONB NOT NULL,
    previous_event_hash   BYTEA NOT NULL,
    event_signature       BYTEA NOT NULL
);
```

Asynchronous mirror to object store as line-delimited JSON, encrypted with backup-master-key (separate from active key).

A tamper-detection job runs hourly, verifies that previous_event_hash chain reconstructs from current rows, and alerts on divergence.

### 11.3 Log redaction

Application logs (zerolog) pass through a redaction middleware that drops these JSON fields by name:

```
cookie, set_cookie, authorization, x-csrf-token, password, secret, token,
session_id, bundle_value, dek, hmac_key, *.value where path matches credentials.*
```

CI test asserts redaction by feeding sample bundles through logger and grepping output.

### 11.4 SIEM integration

CEF-formatted export per event (configurable: syslog UDP, syslog TCP, splunk HEC, Elastic, generic webhook).

```
CEF:0|SentinelCore|DAST|1.0|recording.approved|Recording approved|3|
suser=alice@bank.tld src=10.0.0.5 cs1=dast_auth_bundle cs1Label=resource_type
cs2=<bundle_id> cs2Label=resource_id outcome=success ...
```

Customer-configurable destination per event class (e.g. `recording.acl_violation` → severity 7 immediate).

### 11.5 Metrics (Prometheus)

- `dast_recording_total{status, customer_id}` — counter
- `dast_recording_replay_duration_seconds` — histogram
- `dast_recording_replay_failures_total{reason}` — counter
- `dast_recording_active_count{status}` — gauge (per status)
- `dast_recording_age_seconds` — gauge per active recording
- `dast_bypass_token_verification_total{result}` — counter (from customer SDKs reporting back if telemetry enabled — opt-in)
- `dast_kms_operation_duration_seconds{operation}` — histogram
- `dast_audit_chain_verification_lag_seconds` — gauge (hourly verification job)

### 11.6 Alerts (default rules)

| Alert | Condition | Severity |
|-------|-----------|----------|
| ReplayFailureSpike | `recording.refresh_failed` rate > 10/h for any customer | warn |
| ACLViolation | any `recording.acl_violation` event | critical (immediate page) |
| AuditChainBreak | tamper-detection job reports break | critical |
| BypassSecretRotationOverdue | secret > 13 months old | warn |
| BundleNearExpiry | `expires_at - now < 1h` AND `last_used_at within 24h` | info (notify recorder) |
| KMSLatency | `dast_kms_operation_duration_seconds:p99` > 500ms for 5 min | warn |
| ReplayCircuitBreakerOpen | bundle marked refresh_required AND was approved < 1h ago | warn |

---

## 12. Operational concerns

### 12.1 HA topology

- Controlplane: 3 replicas behind L7 LB; database HA per existing pattern.
- KMS: customer's responsibility (we expect AWS KMS / Azure KV / GCP KMS to provide native HA).
- Audit chain: writes must succeed for any bundle operation to commit (synchronous append). HA Postgres ensures availability; degraded mode rejects new bundle operations rather than skip audit.
- Replay engine: stateless workers; restart-safe.
- Object store: S3 / MinIO with cross-region replication for prod customers.

### 12.2 SLOs

| Metric | Target |
|--------|--------|
| Bundle decryption latency (p99) | < 200 ms |
| Replay end-to-end (p99, automatable) | < 30 s |
| Approval queue latency | Within reviewer's SLA (operational, not technical) |
| Audit chain verification lag | < 1 h |
| KMS rewrap (quarterly) | < 4 h for entire active bundle population |

### 12.3 Key rotation runbook (summary; full doc separate)

| Key | Cadence | Procedure | Risk if skipped |
|-----|---------|-----------|------------------|
| KMS master key | Customer policy (yearly recommended) | Customer-managed via KMS console; SentinelCore detects new version automatically | Reduced cryptographic agility |
| Bundle DEKs | Quarterly | Background job calls KMS rewrap on every active bundle | Compromised wrap doesn't expose plaintext but reduces blast radius window |
| Bundle integrity HMAC key | Quarterly | New key version published; old version retained 90 days; bundles re-HMACed during rewrap | Old HMAC keys retained too long widen forgery window |
| Scanner bypass secret | Yearly per customer | Dual-secret window 30 days; customer must update backend within window | Revealed secret enables CAPTCHA bypass forgery |
| Audit log signing key (Ed25519) | Quarterly | New key version; previous key retained for verification 7 years | Audit forgery window post-key-leak |

### 12.4 Backup & disaster recovery

- **Backup encryption key** is separate from active operational keys. Generated yearly, stored in air-gapped HSM/escrow per customer policy.
- **Restore drill** quarterly: random subset of bundles restored from backup to staging; integrity verified; results audited.
- **RPO**: 1 hour (Postgres + S3 cross-region replication).
- **RTO**: 4 hours for full DAST scanner functionality post-region-failure.
- **Retention**: 7 years for audit log (banking); 30 days post-deletion for bundle ciphertext (with destroyed DEK — audit-only, decryption impossible).

### 12.5 Pen-testing & security review cadence

- External pen-test before each major release (yearly minimum).
- Internal red-team exercise quarterly.
- Threat-model review yearly or after any significant architectural change.
- Cryptographic review on every change touching `internal/kms/` or `internal/authbroker/recording/`.

### 12.6 Change management

- All changes to recording/replay code paths require:
  - Two-reviewer code review (at least one with SecOps tag).
  - Security regression suite must pass (Section 13.3).
  - Audit log schema changes are versioned; old rows retain old schema_version and remain verifiable.

---

## 13. Test strategy

### 13.1 Unit tests

- Each strategy: `Authenticate`, `Refresh`, `Validate` happy path + every error path.
- KMS adapter for each provider: round-trip encryption + tampering detection.
- HMAC token: format parse + verify success + each failure mode (expired, wrong host, wrong nonce, replay).
- Recorder action capture: event sequence → canonical JSON identity (deterministic).
- Replayer: each pre-flight check, action execution edge cases, scope violation.

### 13.2 Integration tests

- Full record → upload → approve → use → audit chain verification.
- Dual-secret rotation window: token signed with old secret, new secret accepts within window, neither outside.
- Soft-delete → grace period → hard-delete → audit retained.
- Revoke during in-flight scan → replay aborts within 2 seconds.

### 13.3 Security regression suite

Runs in CI, must remain green. Each test corresponds to a STRIDE threat in §2.3:

| ID | Test |
|----|------|
| sec-01 | Tampered bundle: modify ciphertext → integrity HMAC fails → rejected |
| sec-02 | Tampered bundle: swap wrapped DEK → unwrap fails or yields wrong key → rejected |
| sec-03 | Tampered bundle: edit metadata not in HMAC scope → would-be missed; assert all relevant metadata IS in HMAC scope |
| sec-04 | Forged action list: extra navigate to attacker-host → pre-flight scope fails |
| sec-05 | Forged token: HMAC over different target_host → rejected by SDK |
| sec-06 | Replay attack: same token used twice → second rejected |
| sec-07 | Token outside time window → rejected |
| sec-08 | ACL violation: scan from wrong project → rejected |
| sec-09 | Approver == recorder → DB trigger rejects |
| sec-10 | Revoked bundle decryption → DEK destroyed → unrecoverable |
| sec-11 | Audit chain mutation → tamper-detection job alerts |
| sec-12 | Log redaction: feed bundle through logger → no credential bytes appear |
| sec-13 | Memory dump simulation: trigger panic with bundle in scope → core dump empty (RLIMIT_CORE = 0) |
| sec-14 | Replay rate limit: exceed → circuit opens |
| sec-15 | Recording principal mismatch → scan rejected |
| sec-16 | Sensitive selector capture → field hash, not literal, in bundle |

### 13.4 Fuzzing

- Bundle parser: `go-fuzz` against canonical JSON deserializer.
- Token parser: fuzz against all field positions and lengths.
- HMAC verifier: ensure constant-time comparison.

### 13.5 Penetration testing

- Pre-release engagement: external firm with banking-DAST experience.
- Scope: recording capture, bundle storage, replay, scanner bypass token forgery, RBAC bypass, audit log tampering.
- Report tracked as PR; high/critical findings block release.

### 13.6 Performance & chaos

- 1000 concurrent scans, each with fresh recording load → KMS rate not breached, audit chain doesn't lag > 1h.
- KMS provider latency spike (chaos: inject 5s p50) → graceful degradation, scans queue rather than fail.
- Postgres replica lag spike → audit writes still succeed against primary.

---

## 14. Phased rollout

### 14.1 Phase 0 — infrastructure (week 1)

- KMS adapter implementation + tests (AWS KMS minimum; Vault Transit fallback for local dev).
- `dast_auth_bundles` schema migration + indexes.
- `audit_events` table + signing key plumbing.
- `internal/kms/`, `internal/audit/` packages stub-tested.

### 14.2 Phase 1 — MVP (weeks 2-3)

- `SessionImportStrategy` with bundle CRUD, KMS encryption, audit logging.
- Scanner bypass token issuer + verifier + Go SDK.
- Approval workflow (basic): pending_review, approved, revoked states.
- 4-eyes enforcement (DB trigger + middleware).
- Web UI: bundle list + manual upload + approval queue.
- Security regression tests sec-01…sec-12.
- Documentation: customer onboarding, bypass secret setup.

### 14.3 Phase 2 — recording (weeks 4-5)

- CLI: `sentinelcore dast record` (chromedp-based; reuses existing browser package).
- Recorder UI integrations: action capture, sensitive-field detection, Vault hand-off.
- `RecordedLoginStrategy` with one-shot mode.
- Bundle metadata (browser fingerprint, action count, principal extraction).
- Tests sec-13…sec-16.

### 14.4 Phase 3 — automatable replay (week 6)

- Replay engine in `internal/authbroker/recording/replayer.go`.
- Pre-flight checks, post-state assertion, anomaly detection, circuit breaker.
- TTL-driven refresh scheduler.
- `automatable_refresh` flag in approval UI.

### 14.5 Phase 4 — operational completeness (weeks 7-8)

- Customer SDKs: Java (Spring), Python (Flask + Django), .NET (ASP.NET Core), Node (Express).
- SIEM CEF/syslog export.
- Prometheus metrics + alert rules.
- Backup encryption + restore drill.
- Documentation: runbooks (key rotation, secret compromise, restore, kill-switch).

### 14.6 Phase 5 — pre-GA hardening (weeks 9-10)

- External penetration test.
- Compliance review with banking customer's audit team.
- Performance / chaos tests at scale.
- 1 banking pilot customer rolls out in their staging.
- Findings remediated; audit attestation collected.
- GA criteria: zero critical pen-test findings, audit chain operational for 2 weeks without break, customer pilot scan succeeds end-to-end.

### 14.7 Rollback & feature flags

Each phase ships behind a per-customer feature flag (`feat.dast_recording`, `feat.scanner_bypass_token`). Flags default off; banks opt in explicitly. Rollback = flag off + revert deployment; bundles in storage unaffected (forward-compatible schema).

### 14.8 GA exit criteria

- All 16 security regression tests green for 30 days.
- Audit chain integrity verified hourly without break for 30 days.
- 99.9% KMS operation success rate over 30 days.
- Pen-test report with zero critical and zero high findings (or remediated).
- 1 banking pilot customer in active production-mirror scanning.
- Compliance attestation document signed by customer's CISO.

---

## Appendix A — open questions for review

1. **KMS provider matrix:** which providers do we support at launch? AWS KMS + Vault Transit for v1; add Azure KV + GCP KMS in v1.1?
2. **Per-customer egress IPs:** does every banking customer require allowlistable scanner egress IPs? Implementation needs network-level config.
3. **Recording duration cap:** 10 min may be insufficient for multi-step KYC-style flows. Make customer-configurable up to 30 min?
4. **Cross-region bundle storage:** EU customers may require bundle storage to remain in-region (KVKK + GDPR locality). Schema needs region tag.
5. **MFA in recording:** TOTP-based MFA can be replayed if seed is in Vault. Push-based and WebAuthn cannot. Document scope explicitly.
6. **Action selector stability:** SPA frameworks (React/Vue) often regenerate selectors per build. Recommend customers add `data-testid` to login flow for replay stability.

---

## Appendix B — glossary

- **Bundle**: encrypted container holding action list + captured session + metadata for a recording.
- **One-shot recording**: recording whose flow includes CAPTCHA or other non-replayable elements; usable until session TTL only.
- **Automatable recording**: recording whose flow can be re-run without human input; supports indefinite refresh.
- **Scanner bypass token**: HMAC-signed header that customer back-ends recognize to skip CAPTCHA / rate-limit / MFA for verified scanner traffic.
- **Replay engine**: subsystem that runs a recording's action list in a sandboxed Chrome to obtain a fresh session.
- **DEK**: data encryption key; per-bundle AES-256 key wrapped by KMS.
- **Kill switch**: customer-initiated immediate revocation of an active bundle, destroying its DEK.
- **4-eyes principle**: separation of duties between recorder and reviewer, enforced by DB and IAM.
- **Tamper-evident audit chain**: append-only audit log with hash chain, allowing detection of any retroactive modification.
