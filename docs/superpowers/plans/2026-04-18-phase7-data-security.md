# Phase 7 — Data Security Implementation Plan

> **For agentic workers:** REQUIRED: Use `superpowers:subagent-driven-development` (if subagents available) or `superpowers:executing-plans` to implement this plan. Steps use checkbox (`- [ ]`) syntax.

**Goal:** bring SentinelCore's data-protection posture to the level a regulated-industry buyer (bank, insurer, healthcare) will accept under audit. Unify the encryption / secret / isolation surfaces that today are scattered across env vars, ad-hoc `enc:v1:` encryption, and RLS policies that are bypassed by the owner role.

**Architecture principle:** "nothing important lives in plaintext or in a single place". Every secret has a tier, a storage medium, a rotation schedule, and a blast-radius contract. Every tenant-scoped query goes through a wrapper that sets the RLS context and logs on bypass. Every piece of data at rest is encrypted either by the filesystem, the DB, or the app — with exactly one owner per layer.

**Current baseline (what exists):**

- TLS 1.3 termination at the host-level nginx (`securecontext-nginx`). Backend is plain HTTP inside the docker backend network.
- Password hashing: `bcrypt` via `pkg/auth.HashPassword`. Default cost.
- API key hashing: `SHA-256` via `pkg/apikeys.Hash` (unpeppered).
- SSO provider client_secret: AES-256-GCM app-layer, `enc:v1:` prefix, key from env `SSO_ENC_KEY_B64`.
- Audit HMAC chain: HMAC-SHA256, key from env `AUDIT_HMAC_KEY_B64` (Phase 6).
- Webhook secret: `secret_encrypted BYTEA` + `secret_key_id TEXT` columns (already encrypted; key rotation not yet wired).
- Auth profile secret: `encrypted_secret BYTEA` (already encrypted).
- JWT signing: RS256 via PEM files (`/opt/sentinelcore/env/secrets/jwt_*.pem`, mode 0400).
- RLS: policies exist on `audit.*`, `auth.oidc_providers`, `governance.*`. Owner DB role bypasses them (default for `sentinelcore` user).
- Backup: **none automated**.

**Gap closure targets (what this plan delivers):**

1. Unified `pkg/secrets` interface: one API, two implementations (env-backed today, Vault-backed when Vault is wired).
2. Single AES-master-key catalog — replaces three unrelated keys (`SSO_ENC_KEY_B64`, `AUDIT_HMAC_KEY_B64`, future webhook key) with versioned key material fetched via the secrets interface.
3. API key hash migration: SHA-256 → HMAC-SHA256 with a server-held pepper, so a DB leak alone cannot validate keys.
4. Split DB roles: one role per service (audit_writer, sast_worker, controlplane, read_only). RLS starts enforcing.
5. `pkg/tenant` query wrapper that refuses to run a query without an explicit `org_id` binding; CI lint enforces.
6. Cross-tenant leakage test harness (`test/integration/tenant_isolation_test.go`) that replays every mutating route as tenant A with tenant B's resource id and asserts 404 / 0 rows.
7. Backup pipeline: `pg_basebackup` + zstd + AES-256-GCM encrypted to MinIO (once wired) or to a bind-mounted volume with daily offsite copy, GPG-recipient-signed.
8. Configurable backend TLS: optional PG `sslmode=verify-full` + mTLS between `controlplane ↔ audit-service ↔ postgres` (deferred gate, off by default, switchable via env).

**Tech stack:** Go 1.26, PostgreSQL 16 (RLS, pgcrypto, roles), pgxpool, existing `pkg/crypto/aesgcm`, future HashiCorp Vault, age-encryption for backups (simpler than GPG infrastructure).

**Phase dependencies:**

- Phase 6 audit: `audit.hmac_keys` catalog is the prototype for the unified key catalog; migration 032 already exists.
- Phase 4 governance: `webhook_configs.secret_encrypted` + `secret_key_id` schema already present.
- Phase 3 SSO: AES envelope pattern (`enc:v1:<b64>`) proven in prod.

---

## 1. Final Security Model

A single diagram for the audit:

```
                  ┌──────────────────────────────────────────┐
                  │  Tier 0 — Root secrets                   │
                  │  AES master, HMAC audit, JWT signing     │
                  │  Source: Vault (prod) / env file (dev)   │
                  │  Rotate: quarterly ceremony              │
                  └──────────────────┬───────────────────────┘
                                     │ fetched via pkg/secrets
                                     ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  Tier 1 — Service credentials                                   │
  │  DB password (per-role), Redis AUTH, NATS creds, SMTP, GPG key  │
  │  Source: Vault / env                                            │
  │  Rotate: automatable, 30-day default                            │
  └──────────────────────┬──────────────────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────────────────┐
    │  Tier 2 — Tenant-owned secrets (encrypted with Tier 0 AES)   │
    │  SSO client_secret, webhook HMAC, auth-profile secret,       │
    │  SMTP integration creds, API signing secrets                 │
    │  Source: DB cipher column (BYTEA / TEXT enc:v1:)             │
    │  Rotate: tenant self-service via admin API                   │
    └──────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
       ┌────────────────────────────────────────────────────────┐
       │  Tier 3 — User / session credentials                   │
       │  Password (bcrypt cost 12), API key (HMAC+pepper),     │
       │  TOTP secret (enc:v1:), refresh tokens (session store) │
       │  Rotate: user-driven                                   │
       └────────────────────────────────────────────────────────┘

Cross-cutting:
  – Every tenant-scoped read/write goes through pkg/tenant.Tx(ctx, orgID).
  – Every query ending at `audit.*` or `governance.webhook_configs` must
    name both the table's `org_id` column AND the tenant predicate.
  – Append-only trigger blocks mutations on audit / history tables.
  – Backups: zstd + age (or GPG) + pg_basebackup + WAL archive.
```

Rules expressed as negatives (what MUST NOT happen):

- No secret lives in the git repository. No exceptions. `pre-commit` hook + `TestNoSecretsInSource`.
- No code path INSERTs into a tenant table without an explicit `org_id` bind. Enforced by `TestNoDirectTenantWrites` (same shape as Phase 6's `TestNoDirectAuditLogWrites`).
- No service authenticates to postgres as the table owner (`sentinelcore`). Each service gets a role with the minimum grants it needs.
- No plaintext secret travels through logs. Enforced by the existing `pkg/audit.Redact` in every `Emit` call.
- No unencrypted backup leaves the host. The backup script refuses to upload if the output doesn't start with the age/GPG magic bytes.

---

## 2. Encryption Strategy

**Matrix.** One row per data type; columns say WHERE the protection lives. Missing column = not applicable.

| Data type | At rest | In transit | App-layer | Key source | Rotation |
|---|---|---|---|---|---|
| User password | bcrypt cost ≥ 12 | TLS 1.3 edge | – | – | user-driven |
| API key | **HMAC-SHA256 + server pepper** | TLS | – | pepper in Tier 0 | 1-year max expiry |
| TOTP secret | AES-256-GCM (enc:v1:) | TLS | aesgcm | Tier 0 AES master | user re-enrolment |
| Session token (JWT) | signed RS256 | TLS | – | Tier 0 JWT private key | daily issue |
| Refresh token | Redis key | TLS | – | – | per-session |
| **SSO client_secret** | TEXT enc:v1: | TLS | aesgcm | Tier 0 | tenant admin |
| **Webhook HMAC secret** | BYTEA + key_id | TLS | aesgcm | Tier 0 | tenant admin |
| **Auth profile secret** | BYTEA | TLS | aesgcm | Tier 0 | tenant admin |
| **SMTP/Jira/Slack token** (tenant) | TEXT enc:v1: | TLS | aesgcm | Tier 0 | tenant admin |
| **SMTP server creds** (platform) | env / Vault | TLS submission | – | Tier 1 | 30-day |
| DB password | env file 0640 → Vault | **TLS optional, gated** | – | Tier 1 | 30-day |
| Redis AUTH | env | TLS optional | – | Tier 1 | 30-day |
| NATS nkey/creds | file 0400 | TLS optional | – | Tier 1 | 90-day |
| Audit HMAC key | env → Vault | – | – | Tier 0 | quarterly ceremony |
| AES master key | env → Vault | – | – | Tier 0 | quarterly ceremony (versioned; old keys retained forever) |
| JWT signing key | PEM file 0400 | – | – | Tier 0 | yearly ceremony |
| **Backup artifact** | **age / GPG** encrypted | SFTP / HTTPS | – | recipient pubkey in Vault | key rotation yearly |
| DB on-disk data | host LUKS (operator-provided) | – | pgcrypto for critical fields | host-managed | host-managed |
| Ciphertext columns' IVs | nonce embedded in prefix | – | aesgcm | – | per-record |

**Hashing vs encryption — hard rules:**

- **Hash (one-way):** passwords, API key verifiers. The server only needs `verify(input, stored)`, not `recover(stored)`.
- **Encrypt (two-way):** anything the platform needs to *present back to the user or to the upstream system it's talking to* — OIDC client_secret is sent to the IdP, webhook HMAC is used to sign outbound requests, SMTP credentials are sent to the SMTP relay.
- **Signed (integrity-only):** audit log chain, JWT bearer tokens. Not encrypted; integrity + authenticity are the threat model.

**API key hash migration (SHA-256 → HMAC+pepper):**

Today: `key_hash = sha256(plaintext)`. A DB dump is enough to precompute and validate keys offline. Enterprise auditors flag this.

After migration: `key_hash = hmac_sha256(pepper, plaintext)`, pepper in Vault path `sc/<env>/tier0/apikey-pepper`. A DB dump without the pepper is useless.

Backward compat: two columns, `key_hash` (old) + `key_verifier` (new). Auth path tries `key_verifier` first; on miss AND plaintext provided, falls back to `key_hash` and opportunistically rewrites. Old column dropped after 90-day transition.

**Sensitive field encryption candidates (new):**

- `core.users.phone_number` (when MFA-SMS lands) — TEXT enc:v1:
- `core.users.totp_secret` (when TOTP lands) — TEXT enc:v1:
- `auth.sso_login_events.claims_redacted` — already redacted at emit time; add a runtime assertion that no claim value matching a secret pattern escapes
- `scans.scan_jobs.config_override` — JSONB; confidential config (custom headers, auth tokens) must pass through `pkg/audit.Redact` before INSERT

**Backup encryption:**

```
pg_basebackup → zstd → age (recipient = ops team pubkey) → upload
```

Daily cron via a new `cmd/backup/main.go`. Three layered integrity checks:

1. pg_basebackup provides WAL consistency.
2. zstd frame CRC.
3. age authenticated encryption.

Restoration drill: quarterly, verifies RPO < 1h and RTO < 4h per plan §7.2 in the architecture doc.

---

## 3. Secret Management

### 3.1 `pkg/secrets` interface

```go
// Resolver returns decrypted secret material for a logical path.
// Paths look like "tier0/aes/master" or "tier1/postgres/controlplane".
// Implementations fetch from env (dev) or Vault KV v2 (prod).
type Resolver interface {
    Get(ctx context.Context, path string) ([]byte, error)
    // GetString is the ergonomic shortcut for ASCII secrets.
    GetString(ctx context.Context, path string) (string, error)
    // Version returns a monotonically increasing counter used by the
    // rotation orchestrator to invalidate caches. -1 when unknown.
    Version(ctx context.Context, path string) (int, error)
}
```

Two implementations:

**EnvResolver (dev / transition):** maps paths to env var names via a deterministic translator. `tier0/aes/master` → `SC_T0_AES_MASTER_B64`. Fails fast if the env var is missing.

**VaultResolver (prod when wired):** wraps `github.com/hashicorp/vault/api`. KV v2 mount point `sc/`. Path → `sc/data/<env>/<path>`. Renew token lease every hour.

Caller contract: resolver calls are idempotent and cacheable for ≤ 5 minutes. Callers hold one instance per process, never copy material to globals.

### 3.2 Secret path catalogue

```
tier0/                   ── Root secrets; loss = unrecoverable chain + unauthenticated JWT
  aes/master             AES-256 (32 bytes) for app-layer column encryption.
                         Replaces today's SSO_ENC_KEY_B64.
  hmac/audit             HMAC-SHA256 key for audit.audit_log chain. Versioned.
                         Replaces today's AUDIT_HMAC_KEY_B64.
  apikey/pepper          HMAC-SHA256 key mixed with API key plaintext before hashing.
  jwt/private            RS256 private key (PEM). Today in PEM file.
  jwt/public             RS256 public key (PEM). Same file.

tier1/                   ── Service credentials; rotation schedulable
  postgres/controlplane  DB password for the controlplane DB role.
  postgres/audit-worker  DB password for the INSERT-only audit_writer role.
  postgres/sast-worker   DB password for the SAST worker DB role.
  postgres/readonly      DB password for reporting/export read-only role.
  redis/auth             Redis AUTH if enabled.
  nats/nkey              NATS nkey seed for all services' shared identity.
  smtp/password          Platform-level SMTP relay password for system email.
  backup/age-recipient   age public key the backup job encrypts to.

tier2/                   ── Tenant secrets; NEVER fetched by Resolver directly.
                            Stored IN the DB as ciphertext; decrypted inline
                            using tier0/aes/master via pkg/crypto/aesgcm.
                            Paths here are purely documentation.
  sso/<provider_id>/client_secret
  webhook/<webhook_id>/hmac
  auth_profile/<profile_id>/secret
  integration/<integration_id>/token

tier3/                   ── User secrets
                            Hashes in DB; paths are documentation
  user/<user_id>/password       bcrypt in core.users.password_hash
  user/<user_id>/apikey/<id>    HMAC+pepper in core.api_keys.key_verifier
  user/<user_id>/totp           AES-GCM in core.users.totp_secret_encrypted
```

### 3.3 Rotation strategy

| Tier | Cadence | Mechanism | Zero-downtime? |
|---|---|---|---|
| Tier 0 AES master | quarterly | versioned; writer stamps `key_version`; old keys retained in Vault forever | Yes — new INSERTs use v+1, reads try version-indicated key |
| Tier 0 HMAC audit | quarterly | same as AES master; `audit.hmac_keys` catalog already exists | Yes (Phase 6 ready) |
| Tier 0 API key pepper | yearly | manual ceremony; requires plaintext-less key rotation (users issue new keys, old ones expire naturally) | No — rotation = forced re-issue window |
| Tier 0 JWT signing | yearly | JWKS with key-id; verifier retains previous key for the refresh-token TTL + 24h | Yes |
| Tier 1 DB passwords | 30-day | `sentinelcore-cli rotate-db-password --role=controlplane` → new password written to Vault → service sees lease renewal → reconnects with new password | Yes for short-lived connections (controlplane, workers) |
| Tier 1 SMTP | 30-day | same pattern; SMTP clients reconnect on next send | Yes |
| Tier 2 SSO/webhook/auth secrets | tenant-triggered | tenant admin clicks "rotate"; old secret kept for `grace_period_seconds` (default 600s) so in-flight requests succeed | Yes |
| Tier 3 passwords | user-triggered (reset flow) | standard "forgot password" | Yes |
| Tier 3 API keys | user-triggered (rotate endpoint) | existing `POST /api/v1/api-keys/{id}/rotate` | Yes |

### 3.4 Dev / CI fallback

`pkg/secrets.DefaultResolver()` picks its implementation from `SC_SECRET_BACKEND`:

- `env` (default in dev): all paths resolved via env var name map. Missing var = Fatal at startup.
- `file`: resolver reads `./secrets.local` (mode 0600, gitignored). One path per line: `tier0/aes/master=<b64>`. Used in Docker Compose dev.
- `vault`: VaultResolver with token from `VAULT_TOKEN` / AppRole creds.

`sentinelcore-cli gen-dev-secrets` produces a `secrets.local` file with freshly generated keys for local development.

### 3.5 Audit implications

Every rotation is itself an audit event (from Phase 6 taxonomy):

- `audit.hmac_key.rotated`
- `config.aes_master.rotated` (new code)
- `rbac.permission.granted` on role creation for new DB role
- `audit.tenant_secret.rotated` (new) — emitted by tenant rotate endpoints

The audit emitter's redactor has already been wired (Phase 6 Chunk 3) to drop any field matching `(?i)(secret|password|token|key|hash)`. New rotation endpoints must not explicitly bypass this.

---

## 4. Tenant Isolation Hardening

### 4.1 Threat model

Three classes of leakage we must prevent:

1. **SQL without tenant predicate** — a handler forgets `WHERE org_id = $1`. Current RLS catches this ONLY if the querying role is not the table owner. Today every service runs as owner → RLS is bypassed → this is the biggest real risk.
2. **Path-parameter trust** — a handler accepts `{project_id}` from the URL, loads the project, but doesn't validate the project belongs to the caller's org. Current behaviour: most handlers do validate; some don't.
3. **Background worker cross-tenant write** — a worker processes a NATS message for tenant A but writes a side effect scoped to tenant B (usually via a missing org_id in a derived SQL).

### 4.2 Layered defences

**Layer 1 — DB role split (enforces RLS):**

Four new roles, created via a new migration:

```sql
CREATE ROLE sentinelcore_controlplane LOGIN PASSWORD :pw_cp;
CREATE ROLE sentinelcore_audit_writer LOGIN PASSWORD :pw_aw;
CREATE ROLE sentinelcore_worker       LOGIN PASSWORD :pw_wk;
CREATE ROLE sentinelcore_readonly     LOGIN PASSWORD :pw_ro;

-- Minimal grants (sample — full set in migration 037):
GRANT USAGE ON SCHEMA core, findings, scans, governance, auth TO sentinelcore_controlplane;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA core, findings, scans, governance, auth TO sentinelcore_controlplane;
-- No DELETE. No grants on audit.* beyond read.

GRANT INSERT ON audit.audit_log, audit.risk_events, audit.integrity_checks TO sentinelcore_audit_writer;
GRANT SELECT ON audit.hmac_keys TO sentinelcore_audit_writer;
-- No UPDATE. No DELETE. No access to any tenant schema.
```

RLS policies stay as written in Phase 5/6 migrations. Once the controlplane reconnects as `sentinelcore_controlplane` instead of `sentinelcore`, policies begin enforcing.

Operator ceremony (one-time):

```bash
sentinelcore-cli db-split-roles --apply
# generates Vault entries:
#   sc/tier1/postgres/controlplane
#   sc/tier1/postgres/audit-worker
#   sc/tier1/postgres/worker
#   sc/tier1/postgres/readonly
# updates sentinelcore.env DB_USER + DB_PASSWORD paths accordingly
# recreates containers with new creds
```

**Layer 2 — app-layer `pkg/tenant` wrapper:**

```go
// tenant.Tx starts a transaction, sets app.current_org_id from orgID
// via set_config (tx-local), and passes the resulting pgx.Tx to fn.
// Panics in dev if orgID == "".
func Tx(ctx context.Context, pool *pgxpool.Pool, orgID string,
    fn func(ctx context.Context, tx pgx.Tx) error) error {

    if orgID == "" {
        return ErrNoTenant
    }
    return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{},
        func(tx pgx.Tx) error {
            if _, err := tx.Exec(ctx,
                `SELECT set_config('app.current_org_id', $1, true)`,
                orgID); err != nil {
                return fmt.Errorf("tenant: set context: %w", err)
            }
            return fn(ctx, tx)
        })
}

// QueryRow and Exec are convenience wrappers for common single-statement
// cases — they still set the tenant context under the hood.
func QueryRow(ctx context.Context, pool *pgxpool.Pool, orgID, sql string,
    args ...any) pgx.Row { /* ... */ }
```

Every state-changing handler migrates to `tenant.Tx` or the wrappers. The existing `pkg/db.WithRLS` helper is repurposed as a thin alias.

**Layer 3 — `project_id → tenant_id` validator:**

```go
// ValidateProjectBelongsTo fetches the project's org_id from core.projects
// and returns ErrNotVisible if it doesn't match want. Used at the top
// of every handler that accepts {project_id} in the URL.
func ValidateProjectBelongsTo(ctx context.Context, pool *pgxpool.Pool,
    projectID, wantOrgID string) error {

    var ownerOrg string
    err := pool.QueryRow(ctx,
        `SELECT org_id::text FROM core.projects WHERE id = $1`,
        projectID).Scan(&ownerOrg)
    if errors.Is(err, pgx.ErrNoRows) {
        return ErrNotVisible
    }
    if err != nil {
        return err
    }
    if ownerOrg != wantOrgID {
        return ErrNotVisible
    }
    return nil
}
```

Handlers that take `{project_id}` must call this as their first non-auth step. Code-lint rule (`TestProjectIDValidated`): greps for `r.PathValue("project_id")` / `r.PathValue("id")` in handlers under `/api/v1/projects/{id}/...` and requires `tenant.ValidateProjectBelongsTo` within the same function.

**Layer 4 — static lint:**

A new `TestNoDirectTenantWrites` in `pkg/tenant/lint_test.go` mirrors Phase 6's direct-write lint. Forbidden patterns:

```regexp
(?i)FROM\s+(core|findings|scans|governance|risk)\.[a-z_]+
```

Allowed paths: `pkg/tenant/`, `internal/audit/` (already separately guarded), `internal/governance/*` (tested separately in integration). Everywhere else must route through `tenant.Tx`. Exemptions recorded in `tenantAllowlist` with a reason comment.

**Layer 5 — NATS message envelope carries `org_id`:**

Every NATS message type (scan dispatch, correlation trigger, notification, audit event) already carries `org_id`. Workers SHALL:

1. Read org_id from the message.
2. Call `tenant.Tx(ctx, orgID, ...)` before any DB access.
3. Emit an error event if org_id is empty or unknown — never silently operate without tenant context.

A new integration test `TestWorkerRespectsOrgID` publishes a scan dispatch with a crafted `org_id` and asserts the worker only touches that tenant's tables.

### 4.3 Cross-tenant leakage test harness

`test/integration/tenant_isolation_test.go` runs as a single Go test with:

```go
func TestCrossTenantLeakageMatrix(t *testing.T) {
    env := setupTwoOrgs(t)    // creates orgs A+B with one owner each
    defer env.Cleanup()

    for _, route := range routeCatalogue {
        t.Run(route.Method+" "+route.Path, func(t *testing.T) {
            resourceID := env.CreateResource(route.ResourceKind, env.OrgB.ID)

            // Act as A against B's resource.
            resp := env.CallAs(env.OrgA.Token, route.Method,
                strings.Replace(route.Path, "{id}", resourceID, 1),
                route.Body)

            switch route.Method {
            case "GET":
                // Must return 404, never B's data.
                if resp.StatusCode == 200 {
                    t.Errorf("CROSS-TENANT LEAK: %s %s returned 200 for B's %s",
                        route.Method, route.Path, route.ResourceKind)
                }
            case "POST", "PATCH", "DELETE":
                // Must return 404 or 403; must not mutate B's row.
                if resp.StatusCode < 400 {
                    t.Errorf("CROSS-TENANT MUTATION: %s %s returned %d",
                        route.Method, route.Path, resp.StatusCode)
                }
                env.AssertBResourceUnchanged(t, resourceID)
            }
        })
    }
}
```

`routeCatalogue` is a hand-maintained list of ~60 state-changing routes; the test's first CI run adds every new route that lands in `server.go`. The list is audited quarterly against `routes.go` via `TestRouteCatalogueMatchesServer` so no route escapes coverage.

### 4.4 Anti-footgun patterns for developers

Documented in `docs/tenant-isolation-patterns.md` and enforced at review time:

1. **Never pass `*pgxpool.Pool` into handler logic.** Pass `tenant.Scope` (a thin wrapper that pins an org_id). Handlers call `scope.Query(...)` instead of `pool.Query(...)`.
2. **Never trust `{id}` without validating tenancy.** Use `tenant.ValidateProjectBelongsTo` / `tenant.ValidateOrgOwnership`.
3. **Never return "access denied" and "not found" with different status codes** — leak-by-timing. Uniform 404 for both.
4. **Never log an org_id inside an error message users see.** Log it internally; user sees the generic error.
5. **Never `json.Marshal` a struct that contains `*tenant.Scope`.** Panic at marshal time (zero-value protection).
6. **Never run a bulk update without `WHERE org_id = $1`.** Even platform admins route through `org_id=$1` with `app.audit_global_read='true'` session var (Phase 6 pattern).

---

## 5. Schema Changes

Four new migrations. Numbering picks up from Phase 6's 036.

### 5.1 Migration 037 — DB role split

```sql
BEGIN;

CREATE ROLE sentinelcore_controlplane LOGIN;
CREATE ROLE sentinelcore_audit_writer LOGIN;
CREATE ROLE sentinelcore_worker       LOGIN;
CREATE ROLE sentinelcore_readonly     LOGIN;

-- Passwords set out-of-band by the deploy CLI:
--   sentinelcore-cli db-split-roles --apply
-- which fetches fresh passwords from Vault and runs ALTER ROLE ... PASSWORD.

-- Existing schema ownership stays with 'sentinelcore' role; grants
-- below allow the new roles to USE the schema and access specific tables.

-- Controlplane: read + write on all tenant schemas; NO audit write.
GRANT USAGE ON SCHEMA core, scans, findings, governance, auth, risk TO sentinelcore_controlplane;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA core, scans, findings, governance, auth, risk TO sentinelcore_controlplane;
GRANT SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA core, scans, findings, governance, auth, risk TO sentinelcore_controlplane;
-- Explicit DENY on audit tables (via no grant). controlplane emits to NATS.
GRANT USAGE ON SCHEMA audit TO sentinelcore_controlplane;
GRANT SELECT ON audit.audit_log, audit.risk_events, audit.export_jobs, audit.integrity_checks TO sentinelcore_controlplane;

-- Audit writer: INSERT-only, no tenant access.
GRANT USAGE ON SCHEMA audit TO sentinelcore_audit_writer;
GRANT INSERT ON audit.audit_log, audit.risk_events, audit.integrity_checks TO sentinelcore_audit_writer;
GRANT SELECT, USAGE ON ALL SEQUENCES IN SCHEMA audit TO sentinelcore_audit_writer;
GRANT SELECT ON audit.audit_log, audit.risk_events TO sentinelcore_audit_writer;  -- for previous_hash lookup
GRANT SELECT ON audit.hmac_keys TO sentinelcore_audit_writer;

-- Worker: write scans, findings, risk.clusters; read-only on core.
GRANT USAGE ON SCHEMA core, scans, findings, risk, vuln_intel TO sentinelcore_worker;
GRANT SELECT ON ALL TABLES IN SCHEMA core TO sentinelcore_worker;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA scans, findings, risk TO sentinelcore_worker;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA vuln_intel TO sentinelcore_worker;

-- Readonly: everything SELECT-only; for reports + external SIEM pulls.
GRANT USAGE ON SCHEMA core, scans, findings, governance, auth, risk, audit, vuln_intel TO sentinelcore_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA core, scans, findings, governance, auth, risk, audit, vuln_intel TO sentinelcore_readonly;

-- Default privileges so newly created tables inherit the same grants.
ALTER DEFAULT PRIVILEGES IN SCHEMA core, scans, findings, governance, auth, risk
    GRANT SELECT, INSERT, UPDATE ON TABLES TO sentinelcore_controlplane;

COMMIT;
```

### 5.2 Migration 038 — API key pepper rotation schema

```sql
BEGIN;

-- New verifier column populated at next key create/rotate. Old key_hash
-- stays for the 90-day transition.
ALTER TABLE core.api_keys
    ADD COLUMN IF NOT EXISTS key_verifier TEXT,
    ADD COLUMN IF NOT EXISTS pepper_version INTEGER;

CREATE INDEX IF NOT EXISTS api_keys_verifier_idx
    ON core.api_keys(key_verifier)
    WHERE key_verifier IS NOT NULL;

-- pepper_versions catalog, parallel to audit.hmac_keys.
CREATE TABLE auth.apikey_peppers (
    version     INTEGER PRIMARY KEY CHECK (version > 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ,
    vault_path  TEXT NOT NULL,
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64)
);

INSERT INTO auth.apikey_peppers (version, vault_path, fingerprint)
VALUES (1, 'env:SC_APIKEY_PEPPER_B64',
        '0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (version) DO NOTHING;

COMMIT;
```

### 5.3 Migration 039 — Unified AES master key catalog

Replaces today's three scattered keys (SSO, Audit HMAC, future webhook) with one versioned table. The env var sources are unchanged at first; the catalog indirects lookup.

```sql
BEGIN;

CREATE TABLE auth.aes_keys (
    version     INTEGER PRIMARY KEY CHECK (version > 0),
    purpose     TEXT NOT NULL CHECK (purpose IN ('sso','webhook','auth_profile','integration','generic')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ,
    vault_path  TEXT NOT NULL,
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64)
);

-- Seed the row for today's SSO key.
INSERT INTO auth.aes_keys (version, purpose, vault_path, fingerprint)
VALUES (1, 'sso', 'env:SSO_ENC_KEY_B64',
        '0000000000000000000000000000000000000000000000000000000000000000');

COMMIT;
```

Writers for webhook / auth-profile / integration tables include `aes_key_version INTEGER` alongside their `secret_encrypted BYTEA` column. Rotation = insert v+1 row into `auth.aes_keys`, write new secrets with v+1; re-encrypt background job migrates old rows on a schedule.

### 5.4 Migration 040 — Append-only on tenant-critical tables

Extends Phase 6's append-only trigger helper to the rest of the tamper-sensitive surface:

```sql
BEGIN;

-- Apply audit.prevent_mutation to tables where a compliance auditor
-- would flag silent row edits:
--   - findings.state_transitions  (history already, but trigger missing)
--   - audit.export_jobs           (status progression OK; block row delete)
--   - auth.role_permissions       (grants/revokes are audit events, not edits)
--
-- Where appropriate we allow UPDATE of whitelisted columns only. Example:
-- export_jobs needs UPDATE of (status, progress_rows, finished_at) but not
-- of (org_id, requested_by, requested_at, filters).

CREATE OR REPLACE FUNCTION audit.restrict_columns()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    readonly_cols TEXT[] := TG_ARGV[0]::TEXT[];
    col TEXT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        FOREACH col IN ARRAY readonly_cols LOOP
            EXECUTE format(
                'SELECT CASE WHEN ($1).%1$I IS DISTINCT FROM ($2).%1$I
                   THEN true ELSE false END', col)
            INTO STRICT STRICT
            USING OLD, NEW;
            IF FOUND THEN
                RAISE EXCEPTION
                    'column %.% is immutable after insert',
                    TG_TABLE_NAME, col
                    USING ERRCODE = 'insufficient_privilege';
            END IF;
        END LOOP;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- NOTE: the above is a sketch; actual implementation uses a simpler
-- per-table trigger emitted by a generator since PL/pgSQL can't easily
-- index into a composite by variable column name. See migration body.

CREATE TRIGGER export_jobs_cols BEFORE UPDATE ON audit.export_jobs
    FOR EACH ROW EXECUTE FUNCTION audit.restrict_columns('{id,org_id,requested_by,requested_at,filters,format}');

-- findings.state_transitions is history; no UPDATE / DELETE at all.
CREATE TRIGGER state_transitions_no_mutate BEFORE UPDATE OR DELETE ON findings.state_transitions
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();

COMMIT;
```

---

## 6. Code-Level Enforcement

### 6.1 New packages

```
pkg/secrets/
  resolver.go         # Resolver interface + DefaultResolver()
  env_resolver.go     # EnvResolver (path → env var)
  vault_resolver.go   # VaultResolver (when Vault lands)
  paths.go            # Constants for every canonical path in §3.2
  paths_test.go       # Drift check against docs/secret-path-catalog.md

pkg/tenant/
  tenant.go           # Scope type + Tx + QueryRow + Exec
  validate.go         # ValidateProjectBelongsTo etc.
  scope.go            # Scope binds one org_id; rejects cross-tenant args
  tenant_test.go
  lint_test.go        # TestNoDirectTenantWrites + TestProjectIDValidated

pkg/crypto/
  envelope.go         # Wraps aesgcm.Encrypt with key-version catalog lookup
                      # Returns "enc:v1:..." with v = current master version
  envelope_test.go
```

### 6.2 Handler migration sketch

Before (today):

```go
func (h *Handlers) UpdateProject(w http.ResponseWriter, r *http.Request) {
    user := requireAuth(w, r)
    if user == nil { return }
    id := r.PathValue("id")
    var req updateProjectRequest
    _ = decodeJSON(r, &req)

    _, err := h.pool.Exec(r.Context(),
        `UPDATE core.projects SET display_name = $2 WHERE id = $1`,
        id, req.DisplayName)
    if err != nil { ... }
    // ... leaks: anyone with a valid token can UPDATE any project.
}
```

After:

```go
func (h *Handlers) UpdateProject(w http.ResponseWriter, r *http.Request) {
    user := requireAuth(w, r)
    if user == nil { return }
    id := r.PathValue("id")

    // Layer 3 tenancy validation — fail fast before touching the DB.
    if err := tenant.ValidateProjectBelongsTo(r.Context(), h.pool, id, user.OrgID);
        errors.Is(err, tenant.ErrNotVisible) {
        writeError(w, http.StatusNotFound, "project not found", "NOT_FOUND")
        return
    }

    var req updateProjectRequest
    _ = decodeJSON(r, &req)

    // Layer 2: every tenant-scoped mutation runs inside tenant.Tx.
    err := tenant.Tx(r.Context(), h.pool, user.OrgID, func(ctx context.Context, tx pgx.Tx) error {
        _, err := tx.Exec(ctx,
            `UPDATE core.projects SET display_name = $2 WHERE id = $1 AND org_id = $3`,
            id, req.DisplayName, user.OrgID)
        return err
    })
    if err != nil { ... }
    h.emitProjectScope(...)  // audit event
}
```

Note the explicit `AND org_id = $3` — belt AND braces: RLS is the DB-level guarantee; the predicate in the SQL is the source-code-readable proof.

### 6.3 Lint enforcement

`TestNoDirectTenantWrites` (new), same pattern as Phase 6's audit lint. Allowlist every exempt file with a `//nolint:tenant` comment + reason. CI fails on any unannotated violation.

`TestRouteCatalogueMatchesServer` (new): compares the route list declared in `test/integration/routes.go` against the actual `mux.Handle*` calls in `internal/controlplane/server.go`. Drift fails CI; this is how we keep the cross-tenant matrix honest as the service surface grows.

### 6.4 `pkg/crypto/envelope`

Today's `pkg/crypto/aesgcm.NewEncryptor(key)` is called from every secret-holding package with its own key source. Moving to a single `envelope.Encrypt(ctx, purpose, plaintext)` helper that:

1. Fetches the current key version for `purpose` from `auth.aes_keys` (cached 60s).
2. Resolves the key bytes via `pkg/secrets.Resolver`.
3. Calls `aesgcm.Encrypt`.
4. Returns `enc:v<N>:<b64>` with the key version embedded.

Decrypt path:

1. Strips prefix.
2. Parses `v<N>`.
3. Fetches key for version N (catalog allows arbitrary history).
4. Calls `aesgcm.Decrypt`.

This lets us rotate AES master keys without re-encrypting the world on day one — old rows stay readable, new rows use the new version, a background job lazily re-encrypts.

---

## 7. Test / Validation Plan

**Unit:**

- `pkg/secrets/env_resolver_test.go` — happy path, missing var, malformed base64.
- `pkg/tenant/tenant_test.go` — Tx sets session var, rolls back cleanly on fn error, empty orgID → error.
- `pkg/tenant/validate_test.go` — DB-gated; two orgs, assert `ErrNotVisible` for cross-org `{project_id}`.
- `pkg/crypto/envelope_test.go` — encrypt → decrypt roundtrip with current and past key versions.

**Static lint (run by CI):**

- `pkg/tenant/lint_test.go` — `TestNoDirectTenantWrites` + `TestProjectIDValidated`.
- `pkg/secrets/paths_test.go` — `TestSecretPathsDriftCheck` mirrors the Phase 6 taxonomy drift test.

**Integration (DB + NATS required):**

- `test/integration/tenant_isolation_test.go` — the cross-tenant matrix (§4.3).
- `test/integration/role_split_test.go` — connects as each new DB role, asserts the grants match the plan.
- `test/integration/key_rotation_test.go` — inserts v1 AES key, encrypts row, adds v2 key, encrypts another row, asserts both decrypt; then ages out v1 (deletes from Vault, not from catalog) and asserts v2 rows still work.
- `test/integration/backup_roundtrip_test.go` — runs `sentinelcore-cli backup`, verifies age-encrypted output, restores into a throwaway DB, compares row counts.

**Smoke (prod-adjacent):**

- After role split lands: run `sentinelcore-cli verify-roles` which connects as each role and confirms `SELECT current_user`, `SELECT table_name FROM information_schema.table_privileges WHERE grantee = current_user` matches the grants in the migration.

**Penetration test (pre-release):**

- Attempt `UPDATE audit.audit_log` as the new controlplane role → must fail with `insufficient_privilege`.
- Attempt `INSERT INTO core.projects (org_id = 'ORG_A')` when session var is `ORG_B` → must fail the RLS check.
- Attempt `DELETE FROM findings.state_transitions` → must fail the append-only trigger.

---

## 8. Security Pitfalls to Avoid

1. **Don't re-encrypt the world in one migration.** Rotate the key; let background jobs catch up. A single re-encrypt transaction on a 40 GB audit table is catastrophic.
2. **Don't store the new `key_verifier` without dropping the old `key_hash` on a schedule.** Parallel columns invite "oh I'll fix the lookup later" bugs that leave old hashes forever.
3. **Don't leak the pepper in logs or error messages.** HMAC keys must appear only in the hasher's function scope.
4. **Don't grant the audit_writer role SELECT on any tenant table.** The whole point of splitting is that auditors can't accidentally join across schemas.
5. **Don't set `app.audit_global_read = true` at pool level.** Always tx-local. A leaked session var is a cross-tenant data spill.
6. **Don't skip the cross-tenant test harness on "we don't have time".** Every new route is a potential regression; the matrix is the only defensible proof.
7. **Don't use pgcrypto for secret columns that need key rotation.** pgcrypto's `pgp_sym_encrypt` locks the key into the DB row; our `enc:v<N>:` envelope does not.
8. **Don't trust `r.RemoteAddr` for audit `actor_ip`** — nginx sets X-Forwarded-For. Phase 6's normaliseIP already handles this; don't regress.
9. **Don't let operators `pg_dump` without stripping sensitive columns.** A new `cmd/backup/main.go` handles this; the operator runbook forbids ad-hoc dumps.
10. **Don't rely on RLS as the only tenant check.** RLS is backup; the `AND org_id = $N` predicate in SQL is the primary proof for code reviewers.
11. **Don't keep old AES key material on the same machine as the current one**. Vault separate from the app host; if that's impossible today, at least keep rotated keys in a separate file with different permissions.
12. **Don't version the same way for HMAC and AES.** Different purposes, different rotation schedules; single "key version" is a bug factory. The two tables (`audit.hmac_keys`, `auth.aes_keys`) stay separate.

---

## 9. Rollout Plan

30-day rollout split into three waves. Each wave is independently revertible.

### Wave 1 — Non-breaking infrastructure (week 1)

- [ ] Migration 038 (api_keys.key_verifier column, pepper catalog) — no behaviour change yet; new column is `NULL`.
- [ ] Migration 039 (aes_keys catalog) — seeds current env-backed key as version 1.
- [ ] Migration 040 (append-only triggers on state_transitions + export_jobs).
- [ ] `pkg/secrets` package + EnvResolver; `pkg/crypto/envelope` package.
- [ ] `pkg/tenant` package (Tx, Scope, validators) — no handlers migrate yet.
- [ ] Deploy controlplane + audit-service with new packages in the binary but not yet called.

Revert path: down migrations + prior binary.

### Wave 2 — Handler migration + lint (weeks 2–3)

- [ ] `TestNoDirectTenantWrites` + `TestProjectIDValidated` scaffolded with broad allowlist covering EVERY existing handler (no violations on day 1).
- [ ] Migrate handlers off `h.pool.Query` → `tenant.Tx` in batches of 5/day. Each batch removes its entries from the allowlist; CI keeps us honest.
- [ ] API key hash rewrite: new creates use HMAC+pepper, verifier falls back to old hash on miss, auth path opportunistically backfills.
- [ ] Cross-tenant test harness (`TestCrossTenantLeakageMatrix`) runs in CI with the seed catalogue of routes; scales up as handlers migrate.
- [ ] Pen-test script `scripts/pentest-data-security.sh` runs the 3 attacks from §7 and checks for expected failures.

Revert path: allowlist entries restored; binaries roll back one step.

### Wave 3 — Role split + rotation + backup (week 4)

- [ ] Migration 037 creates the four new DB roles (passwords unset).
- [ ] `sentinelcore-cli db-split-roles --generate-passwords` writes passwords to Vault (or file fallback).
- [ ] Update `/opt/sentinelcore/env/sentinelcore.env` to point each service at its new role's credentials.
- [ ] Recreate containers. Smoke: every existing test still passes; RLS now enforces.
- [ ] Rotation drills:
  - `sentinelcore-cli rotate aes/sso` — creates v2, re-encrypts 5 rows, leaves v1 readable.
  - `sentinelcore-cli rotate hmac/audit` — creates v2, new audit rows use v2, verifier checks both.
  - `sentinelcore-cli rotate apikey-pepper` — opens a 7-day forced-reissue window for user keys.
- [ ] `cmd/backup/main.go` wired as a systemd timer on the host; first age-encrypted backup uploaded.
- [ ] Pen-test script runs again as each new role; expected failures confirmed.

Revert path: re-point env vars at the original `sentinelcore` role; role grants stay in place but are unused. Down migration 037 available for full teardown.

### Exit criteria (compliance sign-off)

- All new DB roles in use; original `sentinelcore` role idle in logs.
- Cross-tenant matrix green for every route in `routes.go`.
- API key pepper rotation completed at least once successfully in staging.
- First age-encrypted backup restored into a staging DB and validated.
- Penetration test script fails all three tamper attempts as expected.
- Operator runbook signed off by security review: rotation, incident response, backup / restore.

---

## Appendix A — File-manifest checklist

```
migrations/
  037_db_roles.up.sql / .down.sql
  038_apikey_pepper.up.sql / .down.sql
  039_aes_key_catalog.up.sql / .down.sql
  040_append_only_extensions.up.sql / .down.sql

pkg/secrets/
  resolver.go, env_resolver.go, vault_resolver.go, paths.go, paths_test.go
pkg/tenant/
  tenant.go, validate.go, scope.go, tenant_test.go, lint_test.go
pkg/crypto/envelope.go (+ _test.go)

cmd/backup/main.go
scripts/pentest-data-security.sh

docs/
  secret-path-catalog.md
  tenant-isolation-patterns.md
  data-security-operator-runbook.md
    (rotation ceremony, backup + restore, role-split drill, incident response)
```

## Appendix B — Key rotation runbook skeleton

```
ROTATE aes/sso
1. Operator runs  sentinelcore-cli rotate aes/sso --generate
2. CLI reads current version from auth.aes_keys WHERE purpose='sso'.
3. CLI generates 32 fresh random bytes.
4. CLI writes to Vault sc/tier0/aes/sso/v{N+1} (or the env-file fallback).
5. CLI INSERTs into auth.aes_keys (version=N+1, purpose='sso', vault_path=...).
6. Controlplane picks up v+1 on next cache refresh (60s max).
7. A background job decrypts each SSO provider's client_secret with v_old,
   re-encrypts with v_new, UPDATEs the row.
8. After full sweep, CLI flips auth.aes_keys.rotated_at on v_old.
9. v_old key material stays in Vault; deletion is manual + dual-control.
```

## Appendix C — Disaster scenarios + responses

| Scenario | Detection | Response |
|---|---|---|
| AES master key leaked | WAF log / GitHub secret scan / honeypot alert | Rotate immediately; revoke the leaked version; force re-encrypt of every tier-2 row; audit all recent decrypts |
| DB dump exfiltrated | File-access log | If pre-pepper migration: assume every API key compromised, forced global reissue. Post-pepper: assume nothing usable, but still rotate pepper and force reissue for defense-in-depth |
| Backup cipher key lost | Age encryption fails at restore | Fall back to older quarterly backup; regenerate age key; re-take baseline |
| Audit HMAC key v_n corrupted in Vault | Verifier reports `audit.hmac_key.missing` | Restore from quarterly key backup; if unrecoverable, the corresponding monthly partitions become "attest-only" — chain broken but rows still usable with compliance sign-off |
| Cross-tenant row discovered in audit | SIEM alert on audit.audit_log with mixed org_ids | Freeze writes (emergency stop), export affected partition, rotate credentials of anyone who may have seen it, file incident report |
