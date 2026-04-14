# Identity & Access Control — Design Spec

**Date:** 2026-04-13
**Status:** Draft
**Scope:** SSO (OIDC), granular RBAC, scoped API keys for SentinelCore

## Problem

SentinelCore's current auth/authz layer is functional but not enterprise-grade:

- **4 hardcoded roles** (`platform_admin`, `security_admin`, `appsec_analyst`, `auditor`) with a code-embedded permission matrix in `internal/policy/rbac.go`. Adding a role or permission requires a code change + deploy.
- **No SSO.** The schema has `identity_provider` and `external_id` columns on `core.users` but no OIDC/SAML handlers exist. Enterprise customers (banks, FSI) require Azure AD, Okta, or Keycloak SSO.
- **API key scopes defined but not enforced.** `core.api_keys.scopes` is a `TEXT[]` column populated at creation but the middleware never validates the scope against the request. Any valid key has effective full access.
- **Permission checks scattered across handlers.** Each handler calls `policy.Evaluate(user.Role, "scans.create")` inline. A missed check silently drops a protection.

This spec defines the upgrade path to:

1. Capability-based RBAC with 5 roles and ~25 permissions stored in DB and enforced at middleware level.
2. OIDC SSO with JIT user provisioning and group→role mapping.
3. Scoped API keys with creation-time privilege-ceiling enforcement and runtime scope checks.

The three subsystems are coupled (all touch the auth middleware) but independently shippable in sequence.

## Decision

Three-phase rollout, each independently shippable:

- **Phase 1 — RBAC refactor (foundation).** Expand roles, introduce DB-backed permission matrix with process-level cache, replace per-handler `policy.Evaluate` with `RequirePermission` middleware decorators.
- **Phase 2 — API key scope enforcement.** Validate scopes at creation time (ceiling = creator's permissions), enforce at middleware level using the same permission vocabulary as RBAC.
- **Phase 3 — OIDC SSO.** Tenant-scoped OIDC provider config, JIT user provisioning, group→role mapping.

The architecture keeps the existing JWT shape (no `perms` claim), Redis session store, bcrypt password hashing, PostgreSQL RLS, and NATS audit emitter. The refactor targets enforcement and configuration — not the transport or crypto layers.

## Architecture

```
Request
  ↓
CORS → Request ID → Logging → Rate limit
  ↓
AuthenticateMiddleware          ← resolves Principal (user JWT or sc_ token)
  ↓
CSRF (cookie flows only)
  ↓
Router
  ↓
RequirePermission(perm)         ← per-route decorator (Phase 1)
  ↓
RLS-wrapped handler
  ↓
Handler body
```

Every authenticated request resolves to exactly one `Principal`:

```go
type Principal struct {
    Kind    string   // "user" or "api_key"
    OrgID   string
    UserID  string   // empty for tenant-owned service accounts
    Role    string   // empty for api_key
    Scopes  []string // empty for user
    KeyID   string   // empty for user
    JTI     string   // empty for api_key
}

func (p Principal) Can(perm string) bool {
    switch p.Kind {
    case "user":     return rbacCache.RoleHasPermission(p.Role, perm)
    case "api_key":  return slices.Contains(p.Scopes, perm)
    }
    return false
}
```

Handlers never branch on `Kind`. `RequirePermission("scans.run")` works identically for both.

## Schema Changes

Five new tables + one alter on `core.users`.

```sql
-- ── RBAC ─────────────────────────────────────────────────────────
CREATE TABLE auth.roles (
    id          TEXT PRIMARY KEY,          -- slug: 'owner', 'admin', 'security_engineer', 'auditor', 'developer'
    name        TEXT NOT NULL,             -- display: 'Owner', 'Admin', ...
    description TEXT NOT NULL,
    is_builtin  BOOLEAN NOT NULL DEFAULT true,   -- false reserved for future per-tenant custom roles
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.permissions (
    id          TEXT PRIMARY KEY,          -- slug: 'risks.read', 'scans.run', 'users.manage'
    description TEXT NOT NULL,
    category    TEXT NOT NULL              -- 'risks', 'scans', 'findings', 'settings', 'users', 'audit', 'api_keys', 'governance', 'webhooks', 'sso'
);

CREATE TABLE auth.role_permissions (
    role_id       TEXT NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES auth.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Migrate core.users.role values and widen the CHECK constraint.
-- Map: platform_admin→owner, security_admin→admin, appsec_analyst→security_engineer, auditor→auditor.
-- 'developer' is new — no existing users to migrate.
ALTER TABLE core.users DROP CONSTRAINT users_role_check;
UPDATE core.users SET role = 'owner'             WHERE role = 'platform_admin';
UPDATE core.users SET role = 'admin'             WHERE role = 'security_admin';
UPDATE core.users SET role = 'security_engineer' WHERE role = 'appsec_analyst';
-- auditor unchanged.
ALTER TABLE core.users ADD CONSTRAINT users_role_check
    CHECK (role IN ('owner', 'admin', 'security_engineer', 'auditor', 'developer'));

-- ── SSO ──────────────────────────────────────────────────────────
CREATE TABLE auth.oidc_providers (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    provider_slug      TEXT NOT NULL,                -- tenant-unique key used in URL paths
    display_name       TEXT NOT NULL,
    issuer_url         TEXT NOT NULL,
    client_id          TEXT NOT NULL,
    client_secret      TEXT NOT NULL,                -- encrypted at rest via pkg/crypto/aesgcm
    scopes             TEXT[] NOT NULL DEFAULT ARRAY['openid','email','profile','groups'],
    default_role_id    TEXT NOT NULL REFERENCES auth.roles(id),
    sync_role_on_login BOOLEAN NOT NULL DEFAULT true,
    enabled            BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, provider_slug)
);

CREATE TABLE auth.oidc_group_mappings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES auth.oidc_providers(id) ON DELETE CASCADE,
    group_claim TEXT NOT NULL,
    role_id     TEXT NOT NULL REFERENCES auth.roles(id),
    priority    INT NOT NULL DEFAULT 100,            -- lower = higher priority
    UNIQUE (provider_id, group_claim)
);

ALTER TABLE auth.oidc_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_providers_isolation ON auth.oidc_providers
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

ALTER TABLE auth.oidc_group_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_group_mappings_isolation ON auth.oidc_group_mappings
    USING (provider_id IN (
        SELECT id FROM auth.oidc_providers
        WHERE org_id = current_setting('app.current_org_id', true)::uuid
    ));

-- ── API keys ─────────────────────────────────────────────────────
ALTER TABLE core.api_keys
    ADD COLUMN IF NOT EXISTS is_service_account BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;
-- scopes column already exists as TEXT[].
ALTER TABLE core.api_keys ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE core.api_keys ADD CONSTRAINT api_keys_principal_check
    CHECK (user_id IS NOT NULL OR is_service_account = true);
```

**Design notes:**

- Role/permission slugs as TEXT PK (not UUID) — stable identifiers referenced in code. No JOIN needed for display.
- OIDC provider `client_secret` encrypted via existing `pkg/crypto/aesgcm`. Never returned by any GET endpoint; only write-only in create/update.
- RLS on all new `auth.*` tables: `org_id` isolation consistent with the rest of the schema.
- `api_keys.user_id` relaxed to nullable to support tenant-owned service accounts (see API key section).

## Role & Permission Matrix

Five built-in roles. ~25 capability permissions grouped by category.

### Roles

| Role | Description |
|---|---|
| `owner` | Full control. Only role that can manage users, manage SSO, or delete the org. Typically 1-2 per tenant. |
| `admin` | Full operational control. Settings, scans, targets, API keys, SSO config. Cannot manage users. |
| `security_engineer` | Day-to-day security work: scans, triage, risk resolution, audit log read. Cannot change settings or manage users/keys. |
| `auditor` | Read-only across the board + audit log. Cannot modify anything. |
| `developer` | Least privilege. Reads risks/findings, acknowledges risks assigned to them. Safe for broad distribution. |

### Permission matrix

```
                             own  adm  sec  aud  dev
── risks ──────────────────────────────────────────
risks.read                    ✓    ✓    ✓    ✓    ✓
risks.resolve                 ✓    ✓    ✓    ·    ·
risks.mute                    ✓    ✓    ✓    ·    ·
risks.reopen                  ✓    ✓    ✓    ·    ·
risks.acknowledge             ✓    ✓    ✓    ·    ✓
── findings ───────────────────────────────────────
findings.read                 ✓    ✓    ✓    ✓    ✓
findings.triage               ✓    ✓    ✓    ·    ·
findings.legal_hold           ✓    ✓    ·    ·    ·
── scans ──────────────────────────────────────────
scans.read                    ✓    ✓    ✓    ✓    ✓
scans.run                     ✓    ✓    ✓    ·    ·
scans.cancel                  ✓    ✓    ✓    ·    ·
── targets ────────────────────────────────────────
targets.read                  ✓    ✓    ✓    ✓    ✓
targets.manage                ✓    ✓    ✓    ·    ·
── governance ─────────────────────────────────────
governance.approvals.read     ✓    ✓    ✓    ✓    ·
governance.approvals.decide   ✓    ✓    ·    ·    ·
governance.estop.activate     ✓    ✓    ✓    ·    ·
governance.estop.lift         ✓    ✓    ·    ·    ·
── settings ───────────────────────────────────────
settings.read                 ✓    ✓    ✓    ✓    ·
settings.manage               ✓    ✓    ·    ·    ·
── users ──────────────────────────────────────────
users.read                    ✓    ✓    ·    ✓    ·
users.manage                  ✓    ·    ·    ·    ·
── api_keys ───────────────────────────────────────
api_keys.read                 ✓    ✓    ·    ✓    ·
api_keys.manage               ✓    ✓    ·    ·    ·
── sso ────────────────────────────────────────────
sso.manage                    ✓    ✓    ·    ·    ·
── audit ──────────────────────────────────────────
audit.read                    ✓    ✓    ✓    ✓    ·
── webhooks ───────────────────────────────────────
webhooks.read                 ✓    ✓    ✓    ✓    ·
webhooks.manage               ✓    ✓    ·    ·    ·
```

### Key distinctions

- **Owner vs Admin:** only Owner can `users.manage`. This prevents an Admin from self-elevating or locking out the Owner. Matches the "root of trust" pattern — exactly one role can change who has access.
- **Security Engineer vs Admin:** SecEng can run scans and triage findings but cannot change settings, manage users, rotate API keys, or configure SSO.
- **Developer:** read-only risks/findings + the single write permission `risks.acknowledge`. Cannot see settings, users, audit, or webhooks. Safe to grant to the entire engineering team.
- **Four-eyes on approvals:** `governance.approvals.decide` is Owner+Admin only. SecEng can request approval but cannot self-approve.
- **Legal hold:** `findings.legal_hold` is Owner+Admin only. SecEng can triage but cannot mark a finding as immutable for legal proceedings.

### Migration behavior

The seed data (roles + permissions + role_permissions) ships as part of the migration. Existing `core.users.role` values are rewritten in-place in the same migration.

Two migration strategies for handling in-flight JWTs carrying old role strings:

1. **Force re-login** — invalidate all JTIs in Redis at deploy time. Clean but causes a 15-minute user-visible disruption.
2. **Compatibility translator** (recommended) — `compatMode` middleware translates old role strings (`platform_admin` → `owner`) at JWT validation time. Zero user disruption. Flag is removed after 14 days.

## OIDC Flow Design

### Configuration model

Each tenant can configure multiple IdPs (e.g., separate Azure tenants for dev/prod). Each provider has a tenant-unique `provider_slug` used in URL paths:

```
GET /api/v1/auth/sso/{org_slug}/{provider_slug}/start
GET /api/v1/auth/sso/{org_slug}/{provider_slug}/callback
```

Org-scoped paths avoid ambiguity when two tenants use Azure AD — each has its own `org_slug` and `provider_slug`.

### SP-initiated login flow

```
1. User visits /login, sees "Sign in with Azure" button (per enabled provider)
   ↓
2. Browser → GET /api/v1/auth/sso/{org}/{provider}/start
   Backend:
     - Generate: state (random 32B), nonce (32B), PKCE verifier (43-128 chars) + challenge (S256)
     - Store in Redis under key sso:state:{state} with TTL 5m:
         { org_id, provider_id, pkce_verifier, nonce, return_to }
     - 302 redirect to IdP authorize URL with:
         client_id, redirect_uri, response_type=code, scope, state,
         nonce, code_challenge, code_challenge_method=S256
   ↓
3. User authenticates at IdP, IdP redirects back
   Browser → GET /api/v1/auth/sso/{org}/{provider}/callback?code=...&state=...
   ↓
4. Backend callback handler:
   a. Load & delete state from Redis (single-use). Reject if missing/expired/wrong org.
   b. POST to IdP token endpoint with code + pkce_verifier + client credentials.
      Receive: id_token, access_token, (refresh_token discarded — we use our own sessions).
   c. Verify id_token:
        - Signature: via IdP JWKS (cached 1h, refreshed on kid miss)
        - iss matches provider.issuer_url
        - aud matches client_id
        - exp in future, iat not in the future
        - nonce matches stored nonce
   d. Extract claims: sub (required), email (required), name, groups[] (if configured).
   e. Look up user:
        SELECT ... FROM core.users
         WHERE org_id = $1 AND identity_provider = $2 AND external_id = $3
      If not found, fall back to (org_id, email) — attaches SSO identity to an existing
      local user rather than creating a duplicate.
   f. If still not found → JIT provisioning:
        - Resolve role from groups[] using auth.oidc_group_mappings
          (lowest-priority value wins when multiple groups match)
        - If no group match, use provider.default_role_id
        - INSERT INTO core.users (..., identity_provider=provider.slug, external_id=sub,
                                   password_hash=NULL, role=<resolved>)
   g. If found via email fallback and identity_provider='local':
        UPDATE users SET identity_provider=<slug>, external_id=<sub>
        (attaches the SSO identity; does not overwrite password_hash — user can still use either)
   h. If found + provider.sync_role_on_login = true:
        Re-evaluate role from groups and UPDATE if changed.
   i. Create session: issue access+refresh JWTs via existing pkg/auth, store JTI in Redis, set cookies.
   j. Emit audit event: auth.sso.login (with provider slug, external_id, jit_created flag).
   k. 302 redirect to stored return_to (default /dashboard).
   ↓
5. User lands on dashboard, authenticated.
```

### Security measures

| Risk | Mitigation |
|---|---|
| CSRF via callback | `state` param, single-use, 5m TTL, org binding verified |
| Code replay | PKCE (S256) |
| ID token replay | `nonce` binding state ↔ id_token |
| Token substitution | Verify `aud` matches `client_id` |
| Stale IdP keys | JWKS cached 1h, force-refresh on `kid` miss |
| Group claim injection | Groups read from verified `id_token`, never from query params |
| Wrong-tenant login | URL carries `org_slug`; callback verifies `state.org_id == url.org_id` |
| IdP-initiated login | Not supported — only SP-initiated. IdP-initiated POST endpoints are common XSRF vectors |
| User-creation race | Unique `(org_id, email)` index + `INSERT ... ON CONFLICT (org_id, email) DO UPDATE` |

### Session semantics after SSO

Same JWT issuer as password login. JTI stored in Redis. SSO-only users (`password_hash IS NULL`) cannot use the password login endpoint — the handler rejects them with `USE_SSO` pointing to the active provider. Mixed-mode users (has both `password_hash` and `external_id`) can use either path.

### Admin UX

New settings page at `/settings/sso` requires `sso.manage`:

- List providers with enable/disable toggle
- Add/edit provider: name, issuer URL, client ID/secret, scopes, default role, sync-role flag
- Group mappings: table of `group_claim → role` with priority
- Test panel: shows most recent 5 SSO login attempts with success/failure + claim payload (secrets redacted)

## API Key Scope Model

### Key anatomy

Format unchanged: `sc_` + 32 hex chars (16 bytes entropy). SHA-256 hashed at rest. Only the prefix (8 chars after `sc_`) is shown in the UI.

### Principal types

| Type | `user_id` | `is_service_account` | Use case |
|---|---|---|---|
| User-owned | set | false | Developer's personal automation token |
| Service-owned | set | true | Human created it, represents a service (CI pipeline). Revoked when creator leaves. |
| Tenant-owned | NULL | true | Organization-level service account. Survives creator departure. Owner/Admin only. |

### Scope vocabulary

Scopes are **identical** to RBAC permission slugs. A key with `scopes = ['scans.run', 'findings.read']` can do exactly those two things regardless of what role the creator has. Unknown scopes are rejected at creation.

### Privilege ceiling (critical)

A key's effective permissions are `scopes ∩ creator_role_permissions`. You cannot create a key with more permissions than you have.

- An Admin who has `users.manage` can create a key with that scope.
- A Security Engineer cannot — creation rejected with 403.

For tenant-owned service accounts the ceiling is frozen at creation. If the creator's role is later downgraded, the service account keeps working. If the creator is deleted, the key survives.

### Issuance flow

```
POST /api/v1/api-keys
Body: {
  name: "CI pipeline",
  description: "GitHub Actions release automation",
  scopes: ["scans.run", "scans.read", "findings.read"],
  expires_in: "90d",            // optional; null = no expiry
  is_service_account: true      // optional; default false
}

Handler:
  1. Require api_keys.manage permission.
  2. Validate every scope exists in auth.permissions (reject unknown).
  3. Validate every scope ⊆ creator's role permissions (reject privilege escalation).
  4. If is_service_account && creator is not Owner/Admin → reject (403).
  5. Generate: raw = "sc_" + hex(16 random bytes). hash = sha256(raw).
  6. INSERT row with prefix=raw[3:11], key_hash=hash, scopes, expires_at.
  7. Emit audit event api_key.create with key_id, scopes, creator, principal type.
  8. Return: { id, prefix, name, scopes, expires_at, plaintext: raw }
     — plaintext shown ONCE, never returned again.
```

The backend never logs the plaintext. Frontend displays it in a one-time modal with explicit warning.

### Verification flow

Middleware extension of the existing `apikeys.Resolve`:

```
1. Token starts with "sc_" → route to API key path
2. hash := sha256(token)
3. SELECT key_id, org_id, user_id, scopes, expires_at, revoked
   FROM core.api_keys WHERE key_hash = $1
4. Reject if:
     - not found                          → 401 INVALID_KEY
     - revoked = true                     → 401 KEY_REVOKED
     - expires_at < now()                 → 401 KEY_EXPIRED
5. Attach Principal { kind: "api_key", ... } to request context.
6. UPDATE last_used_at = now() — fire-and-forget goroutine, not in critical path.
```

### Rotation & revocation

| Operation | Endpoint | Behavior |
|---|---|---|
| Revoke | `DELETE /api/v1/api-keys/{id}` | Sets `revoked = true`. Next request returns 401. Audit event `api_key.revoke`. |
| Rotate | `POST /api/v1/api-keys/{id}/rotate` | Generates new raw, updates hash + prefix + `rotated_at` in one atomic UPDATE. Old raw stops working immediately. Response includes new plaintext (shown once). Audit event `api_key.rotate` with old_prefix + new_prefix. |
| Expiration sweep | Hourly job in retention-worker | Sets `revoked = true` for keys past `expires_at`. Middleware already enforces at request time; this is cleanup. |

### Audit policy

Every key operation emits an audit event. Successful uses are NOT audited per-request (would flood the log); `last_used_at` + request logs capture that. Audited events:

- `api_key.create` — includes scopes, principal type, expires_at
- `api_key.use.denied` — scope check failed; captures which scope was missing
- `api_key.rotate` — with old_prefix, new_prefix
- `api_key.revoke` — manual revocation
- `api_key.auto_expire` — expiration sweep
- `api_key.auto_revoke` — user-owned key revoked because creator's role was downgraded below key's scopes

### Role-downgrade response

When a user's role is downgraded, user-owned API keys with scopes exceeding the new role's permissions are auto-revoked with audit event `api_key.auto_revoke` (reason: `role_downgrade`). Service-account keys (both service-owned and tenant-owned) are unaffected — that's their purpose.

## Middleware & Enforcement

### Principal in context

`Principal` replaces the existing `UserContext` in `pkg/auth/middleware.go`. Attached to `context.Context` via typed key. Handlers pull it with `auth.PrincipalFromContext(ctx)`.

### Middleware chain

```
CORS → Request ID → Logging → Rate limit
  ↓
AuthenticateMiddleware          ← resolves Principal from JWT or sc_ token
  ↓
CSRF (cookie flows only)
  ↓
Router (mux.HandleFunc)
  ↓
RequirePermission(perm)         ← per-route decorator
  ↓
RLS-wrapped handler             ← db.WithRLS() sets org_id/user_id session vars
  ↓
Handler body (no manual permission checks)
```

### Route registration (before/after)

Before:
```go
mux.HandleFunc("POST /api/v1/scans", handlers.CreateScan)
// inside CreateScan:
if !policy.Evaluate(user.Role, "scans.create") { return 403 }
```

After:
```go
mux.Handle("POST /api/v1/scans",
    auth.RequirePermission("scans.run", handlers.CreateScan))
```

Every route declares its permission at registration. Reading `server.go` gives you the full permission surface of the API in one place.

### RBAC cache

Process-level in-memory cache:

```go
type Cache struct {
    mu          sync.RWMutex
    roleToPerms map[string]map[string]struct{}  // role_id → set of permission_ids
    version     int64
}

func (c *Cache) Can(role, perm string) bool     { /* O(1) RLock + map lookup */ }
func (c *Cache) Reload(ctx, pool) error          { /* full reload from auth.role_permissions */ }
```

**Load triggers:**
1. Startup: `cache.Reload()` before HTTP server accepts traffic.
2. Runtime: `LISTEN role_permissions_changed` via `pg_notify`. Admin mutations call `NOTIFY` inside the DDL transaction; all replicas reload within ~10ms.
3. Safety net: scheduled reload every 60s in case a NOTIFY is missed.

Readers use `RLock`; reload swaps the map atomically under `Lock`. Readers never see a partial state.

### Scope validation at key creation

```go
func CreateAPIKey(w, r) {
    p := auth.PrincipalFromContext(r.Context())
    if !p.Can("api_keys.manage") { return 403 }

    for _, scope := range body.Scopes {
        if !rbacCache.HasPermission(scope) { return 400 "unknown scope: "+scope }
        if !p.Can(scope) { return 403 "cannot grant scope you don't have: "+scope }
    }
    // ... generate + insert ...
}
```

This closes privilege escalation via key creation.

### Error responses

| Condition | HTTP | `code` |
|---|---|---|
| No auth header/cookie | 401 | `UNAUTHENTICATED` |
| Invalid/expired JWT | 401 | `SESSION_EXPIRED` |
| Invalid API key | 401 | `INVALID_KEY` |
| Revoked API key | 401 | `KEY_REVOKED` |
| Expired API key | 401 | `KEY_EXPIRED` |
| Missing permission | 403 | `FORBIDDEN` |
| Insufficient scope | 403 | `INSUFFICIENT_SCOPE` |
| Cross-tenant access | 404 | `NOT_FOUND` (don't leak existence) |
| SSO-only user attempts password login | 401 | `USE_SSO` |

Every 403 from `RequirePermission` emits audit event:
```
{ action: "authz.denied", actor_id: principal.UserID, actor_type: principal.Kind,
  result: "failure", details: { required: "scans.run", have: [...] } }
```

### UI gating

Frontend reads user's permissions from new endpoint:

```
GET /api/v1/auth/me
Response: {
  user: { id, email, display_name, role },
  permissions: ["risks.read", "risks.resolve", "scans.read", ...]
}
```

Frontend caches on app load, uses `<Can permission="scans.run">` component to gate UI:

```tsx
<Can permission="scans.run">
  <Button onClick={startScan}>Run Scan</Button>
</Can>
```

UI gating is a **usability hint**, never a security boundary. Every gated button is also server-side enforced. A user who tampers the client still hits 403.

## Rollout Plan

Three phases, each independently shippable. Phase 2 and 3 depend on Phase 1's middleware infrastructure.

### Phase 1 — RBAC refactor (~2 weeks)

| Step | What | Risk |
|---|---|---|
| 1.1 | Migration: create `auth.roles`, `auth.permissions`, `auth.role_permissions`. Seed 5 roles + permission matrix. | Low |
| 1.2 | Migration: rewrite `core.users.role` values. Update CHECK constraint. | Medium — old role names in JWTs. Mitigation: compatMode (1.6). |
| 1.3 | Build `internal/policy/cache.go` with `pg_notify` reload. Unit tests: reload, concurrent read, missed notification recovery. | Low |
| 1.4 | Build `auth.RequirePermission` middleware decorator. Build `Principal` abstraction. Keep `policy.Evaluate` in place temporarily. | Low |
| 1.5 | Migrate every handler from `policy.Evaluate` to `RequirePermission`. ~6 routes per PR. Add integration test hitting every route with each role token. | Medium — missed handlers silently lose checks. Mitigation: grep gate in CI. |
| 1.6 | Add `compatMode` JWT translator: for 14 days, translate old role strings at validation. Remove after window. | Low |
| 1.7 | Expose `GET /api/v1/auth/me`. Frontend `<Can>` component. Gate UI elements. | Low |
| 1.8 | Remove `policy.Evaluate` + old role strings from codebase. | Low (grep-gated) |

**Shippable when:** every route uses `RequirePermission`, integration tests pass with all 5 role tokens, frontend hides buttons the user can't use. No SSO or scope enforcement yet. Existing API keys keep working via the old resolver.

### Phase 2 — API key scopes (~1 week)

| Step | What | Risk |
|---|---|---|
| 2.1 | Migration: add `is_service_account`, `description`, `rotated_at`. Relax `user_id` to nullable with CHECK. | Low |
| 2.2 | Update `pkg/apikeys/apikeys.go`: scope validation + creator ceiling at creation. | Low |
| 2.3 | Wire API key scope enforcement into unified `Principal.Can()`. | Low |
| 2.4 | Backfill existing keys with minimal scopes (`findings.read`, `scans.read`). One week notice to tenants, dashboard banner listing affected keys. | Medium — tightens previously-implicit broader access. |
| 2.5 | Add `POST /api/v1/api-keys/{id}/rotate` endpoint. | Low |
| 2.6 | Hourly expiration sweep in retention-worker. | Low |
| 2.7 | Frontend API keys page: scope picker, rotate/revoke, one-time plaintext modal. | Low |
| 2.8 | Role-downgrade auto-revoke hook: when `core.users.role` is updated, trigger-based function revokes user-owned keys with scopes exceeding new role. | Medium — trigger logic tested in isolation before rollout. |

**Shippable when:** all keys have validated scopes, scope enforcement active, rotation + expiration verified.

### Phase 3 — OIDC SSO (~1.5 weeks)

| Step | What | Risk |
|---|---|---|
| 3.1 | Migration: `auth.oidc_providers`, `auth.oidc_group_mappings`. RLS policies. | Low |
| 3.2 | Build `pkg/sso/oidc.go`: discovery + JWKS cache, authorize URL, token exchange, id_token verification. Use `github.com/coreos/go-oidc/v3` — don't roll own crypto. | Medium — crypto correctness. Test against staging Azure AD + Okta + Keycloak. |
| 3.3 | Callback handler with state/nonce/PKCE. Redis state store 5m TTL. Tests for: expired state, replayed state, mismatched nonce, wrong aud, tampered iss. | Medium |
| 3.4 | JIT provisioning: lookup by (org_id, external_id), fallback by (org_id, email), create if missing. Group→role resolution. | Medium — email-fallback collision with existing password users. Mitigation: attach SSO identity instead of creating duplicate. |
| 3.5 | Settings page: `/settings/sso` — CRUD for providers + group mappings. Test mode with last 5 login payloads. | Low |
| 3.6 | Reject password login for SSO-only users (`password_hash IS NULL`) with `USE_SSO`. | Low |
| 3.7 | Feature flag: SSO endpoints return 404 unless `org.settings.sso_enabled = true`. Opt-in per tenant. | Low |

**Shippable when:** end-to-end login works against staging Azure AD + Okta + Keycloak, JIT provisioning lands users with correct roles, audit events fire, settings page complete.

### Total estimate: ~4 weeks of engineering, sequenced

Phase 1 alone (~2 weeks) delivers most of the enterprise value. Phases 2 and 3 layer independently.

## Security Pitfalls to Avoid

| Pitfall | Mitigation |
|---|---|
| Permission check bypass via missed handler | CI grep for `policy.Evaluate` + integration test hits every route with every role token |
| Privilege escalation via key creation | Creator's permission ceiling enforced at creation time |
| Stale cache after role change | `pg_notify` reload + 60s safety poll + short JWT TTL (15m) + JTI revocation on role change |
| JWT/session desync (JTI revoked but token still valid) | Existing Redis `IsActive(jti)` check preserved |
| Cross-tenant access via forged `org_id` claim | JWT `org_id` never trusted alone — RLS session variable + query predicate also filter |
| OIDC callback tampering | `state` single-use + PKCE + signed `id_token` verification + org binding check |
| SSO user creation race | Unique `(org_id, email)` + `INSERT ... ON CONFLICT DO UPDATE` |
| Service account outliving creator | By design; flagged via `created_by` + `is_service_account=true` in audit |
| Encrypted client_secret leak via logs | `pkg/crypto/aesgcm` redacts in struct tags; explicit `log.Sensitive(field)` pattern |
| Rotation race (old key works during rotation) | Single atomic UPDATE overwrites hash; no grace window |
| Downgraded role retaining broad API keys | Role-downgrade trigger auto-revokes user-owned keys exceeding new role's scopes |
| IdP returning malicious `groups` claim | Groups read only from cryptographically verified `id_token`; never from unsigned sources |
| Insecure random in state/nonce/PKCE | `crypto/rand` only; fail-closed if rand source errors |
| Missing `RequirePermission` on a new route | Lint rule: `mux.Handle` / `mux.HandleFunc` without `RequirePermission` or in the explicit public-routes list → CI failure |

## Testing Considerations

- **Unit tests:** RBAC cache reload concurrency, pg_notify missed-message recovery, PKCE verifier generation/verification, id_token verification with tampered claims.
- **Integration tests:** every route hit with each of the 5 role tokens + a minimal-scope API key + an expired API key + a revoked API key. Assert expected allow/deny matrix.
- **SSO staging tests:** working flows against a containerized Keycloak; manual smoke against Azure AD and Okta test tenants before release.
- **Migration tests:** apply Phase 1 migration on a copy of prod DB, verify no users orphaned, existing JWTs still validate via compatMode.
- **Security tests:** fuzz `state`/`nonce` tampering, replay attacks, callback with missing/wrong parameters.

## Future Extensions

- SAML 2.0 SP-initiated flow (spec mentions as "second" — deferred to a follow-up spec). The schema (`auth.oidc_providers` → generalize to `auth.sso_providers` with `protocol` column) is designed to accommodate SAML providers without a second migration.
- Custom per-tenant roles (`auth.roles.is_builtin = false`). Requires admin UI for role authoring. Permission enforcement unchanged.
- Fine-grained resource-level permissions (project-scoped roles). Out of scope for this spec; requires deeper discussion of the `(principal, permission, resource)` tuple model.
- Hardware token / MFA integration — deferred; enterprise customers typically enforce MFA at the IdP layer (Azure Conditional Access, Okta MFA policies) rather than at the application.
