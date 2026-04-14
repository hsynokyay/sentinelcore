# Phase 3 — OIDC SSO Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tenant-scoped OIDC single sign-on with JIT user provisioning and group→role mapping for Azure AD / Entra ID, Okta, and Keycloak. Preserve the existing password login path for mixed-mode users.

**Architecture:** Introduce two migrations for `auth.oidc_providers` and `auth.oidc_group_mappings` with RLS. Build a small `pkg/sso` package wrapping `github.com/coreos/go-oidc/v3` for discovery + JWKS + id_token verification (never roll own crypto). Add two handlers: `StartSSO` (generates state/nonce/PKCE, stores in Redis, 302s to IdP) and `SSOCallback` (consumes state, verifies id_token, JIT-provisions, mints session). Extend the existing `Login` handler to reject SSO-only users with `USE_SSO`. Ship a settings page at `/settings/sso` gated on `sso.manage`, with a list/add/edit form and a group-mapping editor.

**Tech Stack:** Go 1.26, `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, existing `pkg/crypto/aesgcm` for client_secret-at-rest, existing `pkg/auth` for JWT issuance, Redis for state store, Next.js 16 + React 19 for settings UI.

**Phase dependencies:**
- **Phase 1 (RBAC refactor) must be deployed before this plan starts** — `auth.roles`, `auth.permissions`, `auth.role_permissions`, the `sso.manage` permission, `Principal.Can()`, `RequirePermission` middleware, and the `is_builtin` column on `auth.roles` all come from Phase 1.
- Phase 2 (API key scopes) is **not** required for Phase 3 — this plan is independent.

---

## File Structure

### New files (migrations)

```
migrations/029_oidc_providers.up.sql         # auth.oidc_providers + RLS
migrations/029_oidc_providers.down.sql
migrations/030_oidc_group_mappings.up.sql    # auth.oidc_group_mappings + RLS
migrations/030_oidc_group_mappings.down.sql
migrations/031_sso_login_events.up.sql       # auth.sso_login_events (test-panel history ring)
migrations/031_sso_login_events.down.sql
```

### New files (Go)

```
pkg/sso/
  client.go               # New/Exchange/VerifyIDToken — wraps go-oidc
  client_test.go          # unit tests with a fake provider
  pkce.go                 # GenerateVerifier, ChallengeS256
  pkce_test.go
  state.go                # State struct, MarshalBinary for Redis
  state_test.go
  return_to.go            # ValidateReturnTo (open-redirect guard)
  return_to_test.go
  groups.go               # ResolveRole(groups, mappings, default) — priority order
  groups_test.go

pkg/ssostate/
  redis_store.go          # Put/Take 5-minute single-use state store
  redis_store_test.go

internal/controlplane/api/
  sso.go                  # StartSSO + SSOCallback + SSOLogout handlers
  sso_test.go             # end-to-end callback flow against a fake IdP
  sso_providers.go        # CRUD for provider config (/settings/sso)
  sso_providers_test.go
  sso_group_mappings.go   # CRUD for group→role mappings
  sso_group_mappings_test.go

internal/controlplane/
  sso_login_history.go    # Small query layer reading auth.sso_login_events
```

### Modified files

```
internal/controlplane/api/auth.go               # Login: reject SSO-only users with USE_SSO
internal/controlplane/server.go                 # Register SSO routes, inject provider store
internal/controlplane/routes.go                 # Add 10 new routes (start, callback, logout, 7 CRUD)
pkg/auth/jwt.go                                 # (maybe) — if session JTI needs "sso_provider_id" claim for logout
go.mod / go.sum                                 # github.com/coreos/go-oidc/v3 + x/oauth2
web/app/settings/sso/page.tsx                   # List + enable toggle + add/edit (new)
web/app/settings/sso/[provider]/mappings/page.tsx  # Group mapping editor (new)
web/app/login/page.tsx                          # "Sign in with <Provider>" buttons (when SSO configured)
web/lib/api.ts                                  # sso.list(), sso.providers.create(), etc.
web/lib/hooks.ts                                # useSSOProviders(), useSSOHistory()
```

### Route additions (10)

```
GET  /api/v1/auth/sso/{org}/{provider}/start     (public, no auth)
GET  /api/v1/auth/sso/{org}/{provider}/callback  (public, no auth)
POST /api/v1/auth/sso/logout                     (authenticated)

GET    /api/v1/sso/providers                     sso.manage
POST   /api/v1/sso/providers                     sso.manage
GET    /api/v1/sso/providers/{id}                sso.manage
PATCH  /api/v1/sso/providers/{id}                sso.manage
DELETE /api/v1/sso/providers/{id}                sso.manage

GET    /api/v1/sso/providers/{id}/mappings       sso.manage
POST   /api/v1/sso/providers/{id}/mappings       sso.manage
DELETE /api/v1/sso/providers/{id}/mappings/{mapping_id}  sso.manage

GET    /api/v1/sso/providers/{id}/history        sso.manage  (last 50 login events)
GET    /api/v1/auth/sso/enabled                  public (returns per-org enabled providers for login page)
```

---

## Chunk 1: Database migrations

### Task 1.1: auth.oidc_providers migration

**Files:**
- Create: `migrations/029_oidc_providers.up.sql`
- Create: `migrations/029_oidc_providers.down.sql`

- [ ] **Step 1: Write up migration**

File: `migrations/029_oidc_providers.up.sql`:

```sql
BEGIN;

CREATE TABLE auth.oidc_providers (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    provider_slug      TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    issuer_url         TEXT NOT NULL,
    client_id          TEXT NOT NULL,
    client_secret      TEXT NOT NULL,      -- ciphertext from pkg/crypto/aesgcm; prefixed with "enc:v1:"
    scopes             TEXT[] NOT NULL DEFAULT ARRAY['openid','email','profile','groups'],
    default_role_id    TEXT NOT NULL REFERENCES auth.roles(id),
    sync_role_on_login BOOLEAN NOT NULL DEFAULT true,
    sso_logout_enabled BOOLEAN NOT NULL DEFAULT false,  -- opt-in full SSO logout
    end_session_url    TEXT,                            -- nullable; populated on first callback via discovery
    enabled            BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, provider_slug),
    -- provider_slug is used in URLs; constrain charset to kebab-case alnum.
    CONSTRAINT provider_slug_format CHECK (provider_slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' AND length(provider_slug) BETWEEN 1 AND 64),
    -- issuer_url must be https (reject http — can't verify JWKS fetches otherwise).
    -- Exception for local dev: accept http://localhost / 127.0.0.1.
    CONSTRAINT issuer_url_https CHECK (
        issuer_url ~ '^https://' OR
        issuer_url ~ '^http://(localhost|127\.0\.0\.1)(:[0-9]+)?(/|$)'
    )
);

CREATE INDEX oidc_providers_org_enabled_idx
    ON auth.oidc_providers(org_id, enabled) WHERE enabled = true;

ALTER TABLE auth.oidc_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_providers_isolation ON auth.oidc_providers
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- updated_at trigger (reuses existing set_updated_at() helper from migration 001).
CREATE TRIGGER oidc_providers_set_updated_at
    BEFORE UPDATE ON auth.oidc_providers
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

COMMIT;
```

- [ ] **Step 2: Write down migration**

File: `migrations/029_oidc_providers.down.sql`:

```sql
BEGIN;
DROP TRIGGER IF EXISTS oidc_providers_set_updated_at ON auth.oidc_providers;
DROP INDEX IF EXISTS auth.oidc_providers_org_enabled_idx;
DROP TABLE IF EXISTS auth.oidc_providers CASCADE;
COMMIT;
```

- [ ] **Step 3: Apply in staging**

```bash
psql "$DATABASE_URL" -f migrations/029_oidc_providers.up.sql
psql "$DATABASE_URL" -c "\d auth.oidc_providers"
# Expected: table with 14 columns, RLS enabled, FKs to core.organizations and auth.roles.
```

- [ ] **Step 4: Verify FK to auth.roles resolves (Phase 1 must be applied)**

```bash
psql "$DATABASE_URL" -c "SELECT id FROM auth.roles WHERE is_builtin = true;"
# Expected: owner, admin, security_engineer, auditor, developer.
# If this errors, Phase 1 is not applied — abort this plan.
```

- [ ] **Step 5: Verify CHECK constraints reject bad input**

```sql
-- provider_slug constraint:
INSERT INTO auth.oidc_providers (org_id, provider_slug, display_name, issuer_url, client_id, client_secret, default_role_id)
VALUES ((SELECT id FROM core.organizations LIMIT 1), 'Azure AD', 'x', 'https://ex.com', 'c', 'enc:v1:xx', 'admin');
-- Expected: ERROR violates check constraint "provider_slug_format" (spaces + capitals not allowed).

-- issuer_url constraint:
INSERT INTO auth.oidc_providers (...) VALUES (..., 'ftp://evil', ...);
-- Expected: ERROR violates check constraint "issuer_url_https".

-- Cleanup any test row.
DELETE FROM auth.oidc_providers WHERE provider_slug IN ('test-slug');
```

- [ ] **Step 6: Commit**

```bash
git add migrations/029_oidc_providers.up.sql migrations/029_oidc_providers.down.sql
git commit -m "feat(sso): add auth.oidc_providers table with RLS + slug/issuer constraints"
```

### Task 1.2: auth.oidc_group_mappings migration

**Files:**
- Create: `migrations/030_oidc_group_mappings.up.sql`
- Create: `migrations/030_oidc_group_mappings.down.sql`

- [ ] **Step 1: Write up migration**

File: `migrations/030_oidc_group_mappings.up.sql`:

```sql
BEGIN;

CREATE TABLE auth.oidc_group_mappings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES auth.oidc_providers(id) ON DELETE CASCADE,
    group_claim TEXT NOT NULL,
    role_id     TEXT NOT NULL REFERENCES auth.roles(id),
    priority    INT NOT NULL DEFAULT 100,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider_id, group_claim),
    CONSTRAINT group_claim_len CHECK (length(group_claim) BETWEEN 1 AND 256),
    CONSTRAINT priority_range  CHECK (priority BETWEEN 1 AND 10000)
);

CREATE INDEX oidc_group_mappings_provider_prio_idx
    ON auth.oidc_group_mappings(provider_id, priority, role_id);

ALTER TABLE auth.oidc_group_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_group_mappings_isolation ON auth.oidc_group_mappings
    USING (provider_id IN (
        SELECT id FROM auth.oidc_providers
        WHERE org_id = current_setting('app.current_org_id', true)::uuid
    ));

COMMIT;
```

- [ ] **Step 2: Write down migration**

File: `migrations/030_oidc_group_mappings.down.sql`:

```sql
BEGIN;
DROP TABLE IF EXISTS auth.oidc_group_mappings CASCADE;
COMMIT;
```

- [ ] **Step 3: Apply + verify**

```bash
psql "$DATABASE_URL" -f migrations/030_oidc_group_mappings.up.sql
psql "$DATABASE_URL" -c "\d auth.oidc_group_mappings"
# Expected: 6 columns, RLS enabled, FK cascades on provider delete.
```

- [ ] **Step 4: Commit**

```bash
git add migrations/030_oidc_group_mappings.up.sql migrations/030_oidc_group_mappings.down.sql
git commit -m "feat(sso): add auth.oidc_group_mappings with RLS + priority ordering"
```

### Task 1.3: auth.sso_login_events migration (history ring for admin UI)

**Files:**
- Create: `migrations/031_sso_login_events.up.sql`
- Create: `migrations/031_sso_login_events.down.sql`

- [ ] **Step 1: Write up migration**

File: `migrations/031_sso_login_events.up.sql`:

```sql
BEGIN;

-- Ring buffer of recent SSO attempts per provider. The admin settings page's
-- test panel reads the last 5-50 entries. This is operational diagnostics
-- (which claims came back, which step failed), NOT the authoritative audit
-- log — that still goes through pkg/audit / NATS. We keep this table small
-- with an automatic retention trigger.
CREATE TABLE auth.sso_login_events (
    id           BIGSERIAL PRIMARY KEY,
    provider_id  UUID NOT NULL REFERENCES auth.oidc_providers(id) ON DELETE CASCADE,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    outcome      TEXT NOT NULL,                     -- 'success' | 'callback_error' | 'claim_error' | 'user_error'
    error_code   TEXT,                              -- e.g. 'state_expired', 'nonce_mismatch', 'aud_mismatch'
    external_id  TEXT,                              -- sub claim if decoded
    email        TEXT,                              -- email claim if decoded
    role_granted TEXT,                              -- resolved role if JIT ran
    claims_redacted JSONB,                          -- full claim payload with values masked to 64 chars max; secret-looking fields removed
    ip_address   INET,                              -- from request
    user_agent   TEXT,
    CONSTRAINT outcome_values CHECK (outcome IN ('success','callback_error','claim_error','user_error'))
);

CREATE INDEX sso_login_events_provider_time_idx
    ON auth.sso_login_events(provider_id, occurred_at DESC);

ALTER TABLE auth.sso_login_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY sso_login_events_isolation ON auth.sso_login_events
    USING (provider_id IN (
        SELECT id FROM auth.oidc_providers
        WHERE org_id = current_setting('app.current_org_id', true)::uuid
    ));

-- Cap per-provider history to 500 rows via AFTER INSERT trigger. Avoids
-- unbounded growth from misconfigured providers that fail every callback.
CREATE OR REPLACE FUNCTION auth.sso_login_events_cap()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = auth, pg_catalog
AS $$
BEGIN
    DELETE FROM auth.sso_login_events
    WHERE provider_id = NEW.provider_id
      AND id NOT IN (
          SELECT id FROM auth.sso_login_events
          WHERE provider_id = NEW.provider_id
          ORDER BY occurred_at DESC
          LIMIT 500
      );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sso_login_events_cap_trg
    AFTER INSERT ON auth.sso_login_events
    FOR EACH ROW
    EXECUTE FUNCTION auth.sso_login_events_cap();

COMMIT;
```

- [ ] **Step 2: Write down migration**

```sql
BEGIN;
DROP TRIGGER IF EXISTS sso_login_events_cap_trg ON auth.sso_login_events;
DROP FUNCTION IF EXISTS auth.sso_login_events_cap();
DROP TABLE IF EXISTS auth.sso_login_events CASCADE;
COMMIT;
```

- [ ] **Step 3: Apply + verify cap trigger**

```bash
psql "$DATABASE_URL" -f migrations/031_sso_login_events.up.sql
# Smoke test cap: insert 501 fake rows, assert COUNT(*) ≤ 500.
psql "$DATABASE_URL" <<SQL
WITH p AS (
    INSERT INTO auth.oidc_providers (org_id, provider_slug, display_name, issuer_url, client_id, client_secret, default_role_id)
    VALUES ((SELECT id FROM core.organizations LIMIT 1), 'cap-test', 'x', 'https://ex.com', 'c', 'enc:v1:xx', 'admin')
    RETURNING id
)
INSERT INTO auth.sso_login_events (provider_id, outcome)
SELECT p.id, 'callback_error' FROM p, generate_series(1, 501);
SELECT COUNT(*) FROM auth.sso_login_events WHERE provider_id = (SELECT id FROM auth.oidc_providers WHERE provider_slug = 'cap-test');
-- Expected: 500
DELETE FROM auth.oidc_providers WHERE provider_slug = 'cap-test';  -- cascades
SQL
```

- [ ] **Step 4: Commit**

```bash
git add migrations/031_sso_login_events.up.sql migrations/031_sso_login_events.down.sql
git commit -m "feat(sso): add auth.sso_login_events ring buffer for admin diagnostics"
```

---

## Chunk 2: SSO core library (pkg/sso)

### Task 2.1: PKCE helpers

**Files:**
- Create: `pkg/sso/pkce.go`
- Create: `pkg/sso/pkce_test.go`

- [ ] **Step 1: Write failing tests**

File: `pkg/sso/pkce_test.go`:

```go
package sso

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateVerifier_LengthAndCharset(t *testing.T) {
	v, err := GenerateVerifier()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7636: verifier is 43-128 chars of [A-Za-z0-9-._~].
	if len(v) < 43 || len(v) > 128 {
		t.Fatalf("verifier length %d out of range", len(v))
	}
	re := regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	if !re.MatchString(v) {
		t.Fatalf("verifier has illegal chars: %q", v)
	}
}

func TestGenerateVerifier_Unique(t *testing.T) {
	a, _ := GenerateVerifier()
	b, _ := GenerateVerifier()
	if a == b {
		t.Fatal("verifiers must differ (crypto/rand)")
	}
}

func TestChallengeS256_KnownVector(t *testing.T) {
	// RFC 7636 appendix B test vector:
	//   verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	//   challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got := ChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got != want {
		t.Fatalf("challenge mismatch:\n got=%s\nwant=%s", got, want)
	}
	// Sanity: base64-url-no-pad decodes to 32 bytes (SHA-256).
	raw, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("challenge should decode to 32 bytes, got %d", len(raw))
	}
	if strings.ContainsAny(got, "=+/") {
		t.Fatalf("challenge must be URL-safe no padding: %q", got)
	}
}
```

- [ ] **Step 2: Run test (should fail — no impl)**

Run: `go test ./pkg/sso/ -run TestGenerateVerifier -v`
Expected: FAIL (package doesn't exist yet).

- [ ] **Step 3: Implement**

File: `pkg/sso/pkce.go`:

```go
// Package sso implements OpenID Connect single sign-on flows.
package sso

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateVerifier returns a RFC 7636-compliant PKCE code verifier:
// 64 bytes of crypto-random data, base64url-encoded (no padding).
// That produces 86 chars — well within the 43-128 allowed range.
// Fails closed if the OS random source fails (never returns a weak value).
func GenerateVerifier() (string, error) {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("sso: crypto/rand failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ChallengeS256 returns the PKCE code_challenge for a verifier under the
// S256 method: BASE64URL(SHA256(ASCII(verifier))), no padding.
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run tests (should pass)**

Run: `go test ./pkg/sso/ -run 'TestGenerateVerifier|TestChallengeS256' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/sso/pkce.go pkg/sso/pkce_test.go
git commit -m "feat(sso): PKCE verifier/challenge helpers with RFC 7636 test vector"
```

### Task 2.2: return_to validator

**Files:**
- Create: `pkg/sso/return_to.go`
- Create: `pkg/sso/return_to_test.go`

- [ ] **Step 1: Write table-driven test**

File: `pkg/sso/return_to_test.go`:

```go
package sso

import "testing"

func TestValidateReturnTo(t *testing.T) {
	cases := []struct {
		in       string
		wantOK   bool
	}{
		{"/dashboard", true},
		{"/findings/abc-123?tab=evidence", true},
		{"/settings#section", true},
		{"", false},                                   // empty
		{"//evil.com/x", false},                       // protocol-relative
		{"/\\evil.com", false},                        // backslash trick
		{"http://evil.com/", false},                   // absolute URL
		{"https://evil.com/", false},
		{"javascript:alert(1)", false},                // scheme
		{"//evil.com/a?x=y", false},
		{"/?foo=//evil.com", true},                    // query containing // is harmless
		{"relative", false},                           // must start with /
		{"/  ", false},                                // whitespace-only content
		{"/ok\nX-Header: pwn", false},                 // header injection via LF
		{"/ok\r", false},                              // CR injection
	}
	for _, tc := range cases {
		got := ValidateReturnTo(tc.in)
		if got != tc.wantOK {
			t.Errorf("ValidateReturnTo(%q) = %v, want %v", tc.in, got, tc.wantOK)
		}
	}
}
```

- [ ] **Step 2: Run test (should fail)**

Run: `go test ./pkg/sso/ -run TestValidateReturnTo -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

File: `pkg/sso/return_to.go`:

```go
package sso

import "strings"

// ValidateReturnTo enforces the spec's open-redirect guard on the
// return_to query parameter passed to /auth/sso/.../start. The value
// must be a same-origin path: starts with `/`, does not start with `//`
// (protocol-relative URL), contains no scheme indicator, no newlines
// (header-injection), and no leading whitespace.
//
// Returns true iff the value is safe to store in Redis state and later
// use in a Location: header.
func ValidateReturnTo(s string) bool {
	if s == "" {
		return false
	}
	// Must start with `/` and second char must not be `/` or `\`.
	if s[0] != '/' {
		return false
	}
	if len(s) >= 2 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	// Header injection via CR/LF.
	if strings.ContainsAny(s, "\r\n") {
		return false
	}
	// Reject whitespace-only-content like "/  ".
	if strings.TrimSpace(s) == "/" && s != "/" {
		return false
	}
	// Reject scheme-looking paths (":" before any slash is a scheme,
	// "/foo:bar" is fine because ":" follows the leading slash).
	// We check the first 32 chars is enough to catch javascript: and
	// data:, while allowing legitimate `:` later in query strings.
	head := s
	if len(head) > 32 {
		head = s[:32]
	}
	if idx := strings.Index(head, ":"); idx > 0 {
		// `:` appears before any `/`-delimited path segment → scheme.
		if !strings.ContainsAny(head[:idx], "/?#") {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/sso/ -run TestValidateReturnTo -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/sso/return_to.go pkg/sso/return_to_test.go
git commit -m "feat(sso): return_to validator rejects open-redirect + header-injection"
```

### Task 2.3: Group → role resolver

**Files:**
- Create: `pkg/sso/groups.go`
- Create: `pkg/sso/groups_test.go`

- [ ] **Step 1: Write tests**

File: `pkg/sso/groups_test.go`:

```go
package sso

import "testing"

func TestResolveRole(t *testing.T) {
	// Mappings: priority 1 > 10 > 100 (lower numeric value wins).
	mappings := []GroupMapping{
		{Group: "sec-engs", Role: "security_engineer", Priority: 10},
		{Group: "admins",    Role: "admin",              Priority: 1},
		{Group: "auditors", Role: "auditor",            Priority: 100},
	}
	defaultRole := "developer"

	cases := []struct {
		name   string
		groups []string
		want   string
		wantFromMapping bool
	}{
		{"no groups → default", nil, "developer", false},
		{"unrecognized group → default", []string{"random"}, "developer", false},
		{"single match: auditor", []string{"auditors"}, "auditor", true},
		{"two matches: priority wins", []string{"auditors", "sec-engs"}, "security_engineer", true},
		{"all three: admin wins by priority", []string{"auditors", "sec-engs", "admins"}, "admin", true},
		{"tie broken by role_id asc", []string{"A", "B"}, "role_a", true},  // see tie-breaker test below
		{"case-sensitive match", []string{"SEC-ENGS"}, "developer", false}, // not "sec-engs"
	}

	// Main table:
	for _, tc := range cases[:5] {
		got, ok := ResolveRole(tc.groups, mappings, defaultRole)
		if got != tc.want || ok != tc.wantFromMapping {
			t.Errorf("%s: ResolveRole(%v) = (%q, %v), want (%q, %v)",
				tc.name, tc.groups, got, ok, tc.want, tc.wantFromMapping)
		}
	}

	// Tie-breaker test (separate mapping set):
	tieMappings := []GroupMapping{
		{Group: "A", Role: "role_b", Priority: 5},
		{Group: "B", Role: "role_a", Priority: 5},
	}
	got, ok := ResolveRole([]string{"A", "B"}, tieMappings, "developer")
	if got != "role_a" || !ok {
		t.Errorf("tie broken ASC: got=%q ok=%v, want role_a/true", got, ok)
	}

	// Case-sensitive:
	got, ok = ResolveRole([]string{"SEC-ENGS"}, mappings, defaultRole)
	if got != "developer" || ok {
		t.Errorf("case-sensitive: got %q ok=%v, want developer/false", got, ok)
	}
}
```

- [ ] **Step 2: Run test (fails)**

Run: `go test ./pkg/sso/ -run TestResolveRole -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

File: `pkg/sso/groups.go`:

```go
package sso

import "sort"

// GroupMapping is one row from auth.oidc_group_mappings.
// Lower Priority value wins; ties broken by Role ASC (for determinism).
type GroupMapping struct {
	Group    string
	Role     string
	Priority int
}

// ResolveRole picks the best role for an incoming set of IdP group
// claims. Returns (role, fromMapping): fromMapping=false means the
// default role was used.
//
// Algorithm:
//   1. Filter mappings to those whose Group appears in groups[].
//   2. Sort by (Priority ASC, Role ASC) for deterministic tie-breaking.
//   3. Pick the first. If empty, return (defaultRole, false).
func ResolveRole(groups []string, mappings []GroupMapping, defaultRole string) (string, bool) {
	if len(groups) == 0 || len(mappings) == 0 {
		return defaultRole, false
	}
	inSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		inSet[g] = struct{}{}
	}
	matched := make([]GroupMapping, 0, len(mappings))
	for _, m := range mappings {
		if _, ok := inSet[m.Group]; ok {
			matched = append(matched, m)
		}
	}
	if len(matched) == 0 {
		return defaultRole, false
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Priority != matched[j].Priority {
			return matched[i].Priority < matched[j].Priority
		}
		return matched[i].Role < matched[j].Role
	})
	return matched[0].Role, true
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/sso/ -run TestResolveRole -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/sso/groups.go pkg/sso/groups_test.go
git commit -m "feat(sso): group→role resolver with priority + deterministic tie-break"
```

### Task 2.4: OIDC client wrapper

**Files:**
- Create: `pkg/sso/client.go`
- Create: `pkg/sso/client_test.go`

- [ ] **Step 1: Add dependencies**

```bash
go get github.com/coreos/go-oidc/v3
go get golang.org/x/oauth2
go mod tidy
```

- [ ] **Step 2: Write fake-IdP integration test**

File: `pkg/sso/client_test.go`:

```go
package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// startFakeIdP returns a test server exposing OIDC discovery + JWKS + a
// precomputed id_token matching the supplied claims. Used to drive the
// Exchange/Verify path end-to-end without hitting a real IdP.
func startFakeIdP(t *testing.T, claims map[string]any) (issuerURL string, idToken string) {
	t.Helper()
	// ... standard pattern: generate RSA key, publish JWKS, sign id_token,
	// mount /.well-known/openid-configuration + /jwks + /token endpoints.
	// Omitted here for brevity — see pkg/sso/testing_test.go helper.
	return "", ""
}

func TestClient_VerifyIDToken_HappyPath(t *testing.T) {
	issuer, tok := startFakeIdP(t, map[string]any{
		"sub":   "user-123",
		"email": "alice@example.com",
		"aud":   "client-abc",
		"iss":   "placeholder",
		"nonce": "n-original",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Add(-1 * time.Minute).Unix(),
		"groups": []string{"admins"},
	})
	_ = issuer
	client, err := New(context.Background(), Config{
		IssuerURL:    issuer,
		ClientID:     "client-abc",
		ClientSecret: "s",
		RedirectURL:  "https://sc.example.com/cb",
		Scopes:       []string{"openid", "email", "groups"},
	})
	if err != nil {
		t.Fatal(err)
	}

	claims, err := client.VerifyIDToken(context.Background(), tok, "n-original")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "user-123" {
		t.Errorf("sub mismatch: %s", claims.Sub)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email mismatch: %s", claims.Email)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "admins" {
		t.Errorf("groups mismatch: %v", claims.Groups)
	}
}

func TestClient_VerifyIDToken_NonceMismatch(t *testing.T) {
	issuer, tok := startFakeIdP(t, map[string]any{"nonce": "n-actual", "sub": "u", "email": "e@x", "aud": "c", "iss": "placeholder", "exp": time.Now().Add(5*time.Minute).Unix()})
	_ = issuer
	client, _ := New(context.Background(), Config{IssuerURL: issuer, ClientID: "c"})
	_, err := client.VerifyIDToken(context.Background(), tok, "n-expected")
	if err == nil || !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected ErrNonceMismatch, got %v", err)
	}
}

func TestClient_VerifyIDToken_AudMismatch(t *testing.T) {
	// aud claim is "other-client", client configured with "client-abc" → fail.
}

func TestClient_VerifyIDToken_Expired(t *testing.T) {
	// exp in the past → fail.
}

func TestClient_VerifyIDToken_TamperedSignature(t *testing.T) {
	// Flip one character in the signature segment → fail.
}

var _ = rand.Reader
var _ = rsa.GenerateKey
var _ = json.Marshal
var _ = httptest.NewServer
var _ = http.StatusOK
var _ = jwt.SigningMethodRS256
var _ = oidc.ProviderConfig{}
var _ = oauth2.Endpoint{}
```

(Full test body including `startFakeIdP` helper should be written out in `pkg/sso/testing_test.go` — this is a sketch; the implementing agent should flesh out the helper following standard Go fake-IdP patterns. See `github.com/coreos/go-oidc/v3/oidc/example_test.go` for a reference.)

- [ ] **Step 3: Run test (fails — no impl)**

Run: `go test ./pkg/sso/ -run TestClient -v`
Expected: FAIL (package not complete).

- [ ] **Step 4: Implement client**

File: `pkg/sso/client.go`:

```go
package sso

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrNonceMismatch   = errors.New("sso: id_token nonce does not match stored nonce")
	ErrIssuerMismatch  = errors.New("sso: id_token issuer does not match provider")
	ErrAudMismatch     = errors.New("sso: id_token audience does not match client_id")
	ErrTokenExpired    = errors.New("sso: id_token expired")
	ErrClaimsMalformed = errors.New("sso: id_token claims could not be parsed")
)

// Config is the minimum set needed to construct an OIDC client for one
// provider. Corresponds to a single row in auth.oidc_providers.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Claims holds the subset of id_token claims we use. Everything else
// is retained in Raw for diagnostics / auditing (with secrets redacted).
type Claims struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	Raw    map[string]any
}

// Client wraps a cached go-oidc Provider + oauth2.Config pair.
// Construction performs discovery (1 HTTP call) + JWKS fetch (1 more);
// callers should cache Client instances per-provider in the controlplane
// rather than constructing fresh ones per request.
type Client struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Cfg    oauth2.Config
	issuerURL    string
	clientID     string
}

// New performs OIDC discovery against cfg.IssuerURL and returns a ready
// Client. Uses the passed ctx for the discovery HTTP call; subsequent
// operations take their own ctx.
//
// Note: go-oidc refuses to talk to HTTP endpoints (discovery MUST be HTTPS)
// except when the environment allows it. For local dev (issuer starts with
// http://localhost) callers should use oidc.InsecureIssuerURLContext.
func New(ctx context.Context, cfg Config) (*Client, error) {
	ctx = maybeInsecure(ctx, cfg.IssuerURL)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("sso: discovery: %w", err)
	}

	return &Client{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: []string{"RS256", "ES256"},
			Now:                  time.Now,
		}),
		oauth2Cfg: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		issuerURL: cfg.IssuerURL,
		clientID:  cfg.ClientID,
	}, nil
}

// AuthorizeURL returns the full URL to 302 the browser to. state, nonce,
// and pkceChallenge must all be generated fresh per login attempt.
func (c *Client) AuthorizeURL(state, nonce, pkceChallenge string) string {
	return c.oauth2Cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange trades an authorization code for an id_token. The caller
// must supply the original PKCE verifier.
func (c *Client) Exchange(ctx context.Context, code, pkceVerifier string) (idToken string, err error) {
	ctx = maybeInsecure(ctx, c.issuerURL)
	tok, err := c.oauth2Cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", pkceVerifier))
	if err != nil {
		return "", fmt.Errorf("sso: token exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", errors.New("sso: token response missing id_token")
	}
	return raw, nil
}

// VerifyIDToken validates signature, iss, aud, exp, and nonce on the
// supplied id_token. Returns the parsed claims on success.
//
// Known error sentinels: ErrNonceMismatch, ErrAudMismatch,
// ErrIssuerMismatch, ErrTokenExpired, ErrClaimsMalformed. Callers SHOULD
// errors.Is-check these to decide the sso_login_events.error_code.
func (c *Client) VerifyIDToken(ctx context.Context, rawIDToken, expectedNonce string) (*Claims, error) {
	ctx = maybeInsecure(ctx, c.issuerURL)
	tok, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		// go-oidc's error messages embed reason; wrap into sentinels.
		switch {
		case containsErr(err, "expired"):
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		case containsErr(err, "aud claim"):
			return nil, fmt.Errorf("%w: %v", ErrAudMismatch, err)
		case containsErr(err, "iss"):
			return nil, fmt.Errorf("%w: %v", ErrIssuerMismatch, err)
		default:
			return nil, fmt.Errorf("sso: id_token verify: %w", err)
		}
	}

	var c1 Claims
	if err := tok.Claims(&c1); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaimsMalformed, err)
	}
	if err := tok.Claims(&c1.Raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaimsMalformed, err)
	}

	// Nonce binding: go-oidc doesn't check nonce — we do it here.
	gotNonce, _ := c1.Raw["nonce"].(string)
	if gotNonce != expectedNonce {
		return nil, ErrNonceMismatch
	}
	return &c1, nil
}

// EndSessionURL returns the provider's end_session_endpoint if discovery
// advertised one. Empty string if not supported.
func (c *Client) EndSessionURL() string {
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = c.provider.Claims(&claims)
	return claims.EndSessionEndpoint
}

func maybeInsecure(ctx context.Context, issuer string) context.Context {
	// Allow http://localhost during dev tests.
	if len(issuer) >= 17 && issuer[:17] == "http://localhost:" {
		return oidc.InsecureIssuerURLContext(ctx, issuer)
	}
	if len(issuer) >= 16 && issuer[:16] == "http://127.0.0.1" {
		return oidc.InsecureIssuerURLContext(ctx, issuer)
	}
	return ctx
}

func containsErr(err error, substr string) bool {
	return err != nil && len(err.Error()) >= len(substr) &&
		(len(substr) == 0 || indexOf(err.Error(), substr) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 5: Flesh out `startFakeIdP` helper**

File: `pkg/sso/testing_test.go`:

Write a helper that:
- Generates a fresh RSA-2048 keypair per test.
- Serves `/.well-known/openid-configuration` with `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` pointing at itself.
- Serves `/jwks` with the public key.
- Serves `/token` returning `{access_token, id_token, token_type: Bearer}` with the supplied id_token signed by the private key.
- Caller supplies claim overrides; helper fills `iss`, `aud`, `exp`, `iat` defaults.
- Returns the issuer URL and the pre-signed id_token string.

(Implementing agent should follow the `github.com/coreos/go-oidc/v3/oidc/example_test.go` pattern.)

- [ ] **Step 6: Run tests**

Run: `go test ./pkg/sso/ -v -count=1`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add pkg/sso/client.go pkg/sso/client_test.go pkg/sso/testing_test.go go.mod go.sum
git commit -m "feat(sso): OIDC client wrapper + fake-IdP test harness"
```

---

## Chunk 3: Redis state store

### Task 3.1: pkg/ssostate/redis_store.go

**Files:**
- Create: `pkg/ssostate/redis_store.go`
- Create: `pkg/ssostate/redis_store_test.go`

- [ ] **Step 1: Write test**

File: `pkg/ssostate/redis_store_test.go`:

```go
package ssostate

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// testRedis returns a real Redis client from TEST_REDIS_URL or skips.
// (Follows the pattern in pkg/auth/session_test.go.)
func testRedis(t *testing.T) *redis.Client {
	t.Helper()
	url := testRedisURL(t)
	opts, _ := redis.ParseURL(url)
	c := redis.NewClient(opts)
	// Flush the DB at start.
	if err := c.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return c
}

func TestStore_PutAndTake(t *testing.T) {
	r := testRedis(t)
	s := New(r)
	ctx := context.Background()

	orig := State{
		OrgID:         "o1",
		ProviderID:    "p1",
		PKCEVerifier:  "v",
		Nonce:         "n",
		ReturnTo:      "/dashboard",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	state := "s-" + randString(t, 32)
	if err := s.Put(ctx, state, orig); err != nil {
		t.Fatal(err)
	}
	got, err := s.Take(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if got.OrgID != orig.OrgID || got.PKCEVerifier != orig.PKCEVerifier || got.Nonce != orig.Nonce {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, orig)
	}
	// Second Take must fail — single-use semantics.
	if _, err := s.Take(ctx, state); err != ErrStateNotFound {
		t.Fatalf("second Take must be ErrStateNotFound, got %v", err)
	}
}

func TestStore_Expires(t *testing.T) {
	r := testRedis(t)
	s := New(r)
	ctx := context.Background()
	state := "s-" + randString(t, 32)
	if err := s.PutWithTTL(ctx, state, State{OrgID: "o"}, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err := s.Take(ctx, state); err != ErrStateNotFound {
		t.Fatalf("expired state should be absent, got %v", err)
	}
}

func TestStore_WrongState(t *testing.T) {
	r := testRedis(t)
	s := New(r)
	if _, err := s.Take(context.Background(), "nonexistent"); err != ErrStateNotFound {
		t.Fatalf("wrong state should be ErrStateNotFound, got %v", err)
	}
}
```

- [ ] **Step 2: Run test (fails)**

Run: `TEST_REDIS_URL="$REDIS_URL" go test ./pkg/ssostate/ -v`
Expected: FAIL (package missing).

- [ ] **Step 3: Implement**

File: `pkg/ssostate/redis_store.go`:

```go
// Package ssostate provides a 5-minute single-use Redis store for
// SSO start-callback state (state token, PKCE verifier, nonce, return_to).
package ssostate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrStateNotFound is returned by Take when the state key does not
// exist (expired, already consumed, or never written). Callers treat
// this identically — do NOT branch on "why" because each reason is
// security-equivalent: the request is invalid.
var ErrStateNotFound = errors.New("ssostate: state not found")

// Default TTL — matches the spec's 5-minute window.
const DefaultTTL = 5 * time.Minute

// State is the payload stashed between /start and /callback.
// Marshaled to JSON for Redis storage.
type State struct {
	OrgID        string    `json:"org_id"`
	ProviderID   string    `json:"provider_id"`
	PKCEVerifier string    `json:"pkce_verifier"`
	Nonce        string    `json:"nonce"`
	ReturnTo     string    `json:"return_to"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Store is the single-use state store.
type Store struct {
	client *redis.Client
}

func New(client *redis.Client) *Store {
	return &Store{client: client}
}

// Put writes state with the default 5-minute TTL.
func (s *Store) Put(ctx context.Context, stateToken string, v State) error {
	return s.PutWithTTL(ctx, stateToken, v, DefaultTTL)
}

// PutWithTTL writes state with an explicit TTL (test helper).
func (s *Store) PutWithTTL(ctx context.Context, stateToken string, v State, ttl time.Duration) error {
	if stateToken == "" {
		return errors.New("ssostate: empty state token")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ssostate: marshal: %w", err)
	}
	return s.client.Set(ctx, stateKey(stateToken), b, ttl).Err()
}

// Take atomically reads + deletes state. Guarantees single-use: any
// second Take with the same token returns ErrStateNotFound.
//
// Uses Redis GETDEL (>=6.2) so there is no race between SET-TTL and
// DEL. If the server is older, fall back to a transactional WATCH/MULTI.
func (s *Store) Take(ctx context.Context, stateToken string) (State, error) {
	if stateToken == "" {
		return State{}, ErrStateNotFound
	}
	raw, err := s.client.GetDel(ctx, stateKey(stateToken)).Bytes()
	if err == redis.Nil {
		return State{}, ErrStateNotFound
	}
	if err != nil {
		return State{}, fmt.Errorf("ssostate: GETDEL: %w", err)
	}
	var v State
	if err := json.Unmarshal(raw, &v); err != nil {
		return State{}, fmt.Errorf("ssostate: unmarshal: %w", err)
	}
	return v, nil
}

func stateKey(t string) string { return "sso:state:" + t }
```

- [ ] **Step 4: Run tests**

Run: `TEST_REDIS_URL="$REDIS_URL" go test ./pkg/ssostate/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/ssostate/redis_store.go pkg/ssostate/redis_store_test.go
git commit -m "feat(sso): 5-minute single-use Redis state store for SSO flow"
```

---

## Chunk 4: Provider CRUD handlers

### Task 4.1: Provider store (DB access)

**Files:**
- Create: `pkg/sso/provider_store.go`
- Create: `pkg/sso/provider_store_test.go`

- [ ] **Step 1: Write store with encrypt-at-rest for client_secret**

File: `pkg/sso/provider_store.go`:

```go
package sso

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/crypto/aesgcm"
)

// Provider is one row of auth.oidc_providers decoded for app use.
// ClientSecret is decrypted on read; never logged.
type Provider struct {
	ID                  string
	OrgID               string
	ProviderSlug        string
	DisplayName         string
	IssuerURL           string
	ClientID            string
	ClientSecret        string   // plaintext — only populated by Get/GetForLogin; NEVER returned in List
	Scopes              []string
	DefaultRoleID       string
	SyncRoleOnLogin     bool
	SSOLogoutEnabled    bool
	EndSessionURL       string
	Enabled             bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ErrProviderNotFound signals a 404 to handlers.
var ErrProviderNotFound = errors.New("sso: provider not found")

// ProviderStore reads/writes auth.oidc_providers.
//
// Tenancy is enforced at the database layer via RLS — the caller MUST
// have set app.current_org_id in the transaction BEFORE invoking any
// of these methods.
type ProviderStore struct {
	pool   *pgxpool.Pool
	crypto *aesgcm.Encryptor // encrypts client_secret at rest
}

func NewProviderStore(pool *pgxpool.Pool, crypto *aesgcm.Encryptor) *ProviderStore {
	return &ProviderStore{pool: pool, crypto: crypto}
}

// List returns providers WITHOUT decrypting client_secret.
// For the settings UI which must never reveal secrets.
func (s *ProviderStore) List(ctx context.Context) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, org_id::text, provider_slug, display_name, issuer_url,
		       client_id, scopes, default_role_id, sync_role_on_login,
		       sso_logout_enabled, COALESCE(end_session_url, ''), enabled,
		       created_at, updated_at
		FROM auth.oidc_providers
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list providers: %w", err)
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.OrgID, &p.ProviderSlug, &p.DisplayName,
			&p.IssuerURL, &p.ClientID, &p.Scopes, &p.DefaultRoleID,
			&p.SyncRoleOnLogin, &p.SSOLogoutEnabled, &p.EndSessionURL,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Get returns a provider with the secret decrypted. Used by the callback
// handler and by the admin "edit" endpoint (which redacts before sending).
func (s *ProviderStore) Get(ctx context.Context, id string) (Provider, error) {
	var p Provider
	var ciphertext string
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, org_id::text, provider_slug, display_name, issuer_url,
		       client_id, client_secret, scopes, default_role_id, sync_role_on_login,
		       sso_logout_enabled, COALESCE(end_session_url, ''), enabled,
		       created_at, updated_at
		FROM auth.oidc_providers WHERE id = $1
	`, id).Scan(&p.ID, &p.OrgID, &p.ProviderSlug, &p.DisplayName,
		&p.IssuerURL, &p.ClientID, &ciphertext, &p.Scopes, &p.DefaultRoleID,
		&p.SyncRoleOnLogin, &p.SSOLogoutEnabled, &p.EndSessionURL,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, fmt.Errorf("get provider: %w", err)
	}
	secret, err := s.crypto.Decrypt(ciphertext)
	if err != nil {
		return Provider{}, fmt.Errorf("decrypt client_secret: %w", err)
	}
	p.ClientSecret = secret
	return p, nil
}

// GetByOrgSlug looks up a provider by (org_slug, provider_slug).
// Used by the public /start + /callback endpoints. Joins through
// core.organizations to resolve the org_slug → org_id.
//
// IMPORTANT: the public endpoints do NOT have app.current_org_id set
// (user isn't authenticated yet), so this method uses a BYPASSRLS path
// — the query itself enforces tenant isolation via the (org.slug, p.provider_slug)
// pair, which is sufficient since both slugs are public IDs.
// The pool used here must be configured with a role that can bypass
// RLS on auth.oidc_providers, OR the method must SET LOCAL
// app.current_org_id after an initial lookup. We take the latter path
// (safer, doesn't require privileged DB role).
func (s *ProviderStore) GetByOrgSlug(ctx context.Context, orgSlug, providerSlug string) (Provider, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Provider{}, err
	}
	defer tx.Rollback(ctx)

	var orgID string
	err = tx.QueryRow(ctx,
		`SELECT id::text FROM core.organizations WHERE slug = $1`, orgSlug).
		Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, err
	}
	// Set RLS context for the provider query.
	if _, err := tx.Exec(ctx, `SET LOCAL app.current_org_id = $1`, orgID); err != nil {
		return Provider{}, err
	}

	var p Provider
	var ciphertext string
	err = tx.QueryRow(ctx, `
		SELECT id::text, org_id::text, provider_slug, display_name, issuer_url,
		       client_id, client_secret, scopes, default_role_id, sync_role_on_login,
		       sso_logout_enabled, COALESCE(end_session_url, ''), enabled,
		       created_at, updated_at
		FROM auth.oidc_providers
		WHERE org_id = $1 AND provider_slug = $2 AND enabled = true
	`, orgID, providerSlug).Scan(&p.ID, &p.OrgID, &p.ProviderSlug, &p.DisplayName,
		&p.IssuerURL, &p.ClientID, &ciphertext, &p.Scopes, &p.DefaultRoleID,
		&p.SyncRoleOnLogin, &p.SSOLogoutEnabled, &p.EndSessionURL,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Provider{}, err
	}

	secret, err := s.crypto.Decrypt(ciphertext)
	if err != nil {
		return Provider{}, fmt.Errorf("decrypt client_secret: %w", err)
	}
	p.ClientSecret = secret
	return p, nil
}

// Create inserts a new provider with the client_secret encrypted.
func (s *ProviderStore) Create(ctx context.Context, p Provider) (string, error) {
	ct, err := s.crypto.Encrypt(p.ClientSecret)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO auth.oidc_providers (
		    org_id, provider_slug, display_name, issuer_url, client_id,
		    client_secret, scopes, default_role_id, sync_role_on_login,
		    sso_logout_enabled, enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id::text
	`, p.OrgID, p.ProviderSlug, p.DisplayName, p.IssuerURL, p.ClientID,
		ct, p.Scopes, p.DefaultRoleID, p.SyncRoleOnLogin,
		p.SSOLogoutEnabled, p.Enabled).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert provider: %w", err)
	}
	return id, nil
}

// Update modifies a provider. If newSecret is empty, the existing
// secret is preserved (edit-without-re-entering-secret flow).
func (s *ProviderStore) Update(ctx context.Context, id string, p Provider, newSecret string) error {
	if newSecret == "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE auth.oidc_providers SET
			    display_name = $1, issuer_url = $2, client_id = $3,
			    scopes = $4, default_role_id = $5,
			    sync_role_on_login = $6, sso_logout_enabled = $7, enabled = $8
			WHERE id = $9
		`, p.DisplayName, p.IssuerURL, p.ClientID,
			p.Scopes, p.DefaultRoleID, p.SyncRoleOnLogin,
			p.SSOLogoutEnabled, p.Enabled, id)
		return err
	}
	ct, err := s.crypto.Encrypt(newSecret)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE auth.oidc_providers SET
		    display_name = $1, issuer_url = $2, client_id = $3, client_secret = $4,
		    scopes = $5, default_role_id = $6,
		    sync_role_on_login = $7, sso_logout_enabled = $8, enabled = $9
		WHERE id = $10
	`, p.DisplayName, p.IssuerURL, p.ClientID, ct,
		p.Scopes, p.DefaultRoleID, p.SyncRoleOnLogin,
		p.SSOLogoutEnabled, p.Enabled, id)
	return err
}

// Delete cascades via FK on group_mappings + sso_login_events.
func (s *ProviderStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM auth.oidc_providers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	return nil
}

// UpdateEndSessionURL is called on successful discovery to cache the
// IdP's end_session_endpoint so SSO logout works without re-running
// discovery on every logout.
func (s *ProviderStore) UpdateEndSessionURL(ctx context.Context, id, endSessionURL string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE auth.oidc_providers SET end_session_url = $1 WHERE id = $2`,
		endSessionURL, id)
	return err
}
```

- [ ] **Step 2: Write store tests**

File: `pkg/sso/provider_store_test.go`:

Cover: Create roundtrip with decrypt, List never returns secret, Update without newSecret preserves, Update with newSecret rotates, GetByOrgSlug returns ErrProviderNotFound for disabled providers, RLS isolation (org A can't see org B's providers).

- [ ] **Step 3: Run tests**

Run: `TEST_DATABASE_URL="$DATABASE_URL" go test ./pkg/sso/ -run TestProviderStore -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add pkg/sso/provider_store.go pkg/sso/provider_store_test.go
git commit -m "feat(sso): provider store with encrypt-at-rest for client_secret"
```

### Task 4.2: Group mapping store

**Files:**
- Create: `pkg/sso/mapping_store.go`
- Create: `pkg/sso/mapping_store_test.go`

- [ ] **Step 1: Implement store**

File: `pkg/sso/mapping_store.go`:

```go
package sso

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type StoredMapping struct {
	ID         string
	ProviderID string
	Group      string
	Role       string
	Priority   int
}

var ErrMappingNotFound = errors.New("sso: group mapping not found")

type MappingStore struct {
	pool *pgxpool.Pool
}

func NewMappingStore(pool *pgxpool.Pool) *MappingStore {
	return &MappingStore{pool: pool}
}

func (s *MappingStore) List(ctx context.Context, providerID string) ([]StoredMapping, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, provider_id::text, group_claim, role_id, priority
		FROM auth.oidc_group_mappings
		WHERE provider_id = $1
		ORDER BY priority ASC, role_id ASC
	`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredMapping
	for rows.Next() {
		var m StoredMapping
		if err := rows.Scan(&m.ID, &m.ProviderID, &m.Group, &m.Role, &m.Priority); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ListForResolver converts StoredMapping → GroupMapping (the struct
// ResolveRole uses). Called by the callback handler.
func (s *MappingStore) ListForResolver(ctx context.Context, providerID string) ([]GroupMapping, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT group_claim, role_id, priority
		FROM auth.oidc_group_mappings
		WHERE provider_id = $1
	`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMapping
	for rows.Next() {
		var m GroupMapping
		if err := rows.Scan(&m.Group, &m.Role, &m.Priority); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (s *MappingStore) Create(ctx context.Context, providerID, group, role string, priority int) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO auth.oidc_group_mappings (provider_id, group_claim, role_id, priority)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (provider_id, group_claim) DO UPDATE
		    SET role_id = EXCLUDED.role_id, priority = EXCLUDED.priority
		RETURNING id::text
	`, providerID, group, role, priority).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert mapping: %w", err)
	}
	return id, nil
}

func (s *MappingStore) Delete(ctx context.Context, providerID, id string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM auth.oidc_group_mappings WHERE id = $1 AND provider_id = $2`,
		id, providerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMappingNotFound
	}
	_ = pgx.ErrNoRows // keep import used if method grows
	return nil
}
```

- [ ] **Step 2: Tests**

File: `pkg/sso/mapping_store_test.go`:

Cover: Create/List/Delete, upsert semantics (Create twice with same group updates), ordering by priority + role_id, RLS isolation.

- [ ] **Step 3: Run**

Run: `go test ./pkg/sso/ -run TestMappingStore -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add pkg/sso/mapping_store.go pkg/sso/mapping_store_test.go
git commit -m "feat(sso): group mapping store with upsert semantics"
```

### Task 4.3: Provider CRUD handlers

**Files:**
- Create: `internal/controlplane/api/sso_providers.go`
- Create: `internal/controlplane/api/sso_providers_test.go`

- [ ] **Step 1: Implement handlers**

File: `internal/controlplane/api/sso_providers.go`:

```go
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/sso"
)

// providerJSON is the wire format. NEVER includes client_secret on read.
type providerJSON struct {
	ID                string   `json:"id"`
	ProviderSlug      string   `json:"provider_slug"`
	DisplayName       string   `json:"display_name"`
	IssuerURL         string   `json:"issuer_url"`
	ClientID          string   `json:"client_id"`
	ClientSecret      string   `json:"client_secret,omitempty"` // write-only; stripped on read
	Scopes            []string `json:"scopes"`
	DefaultRoleID     string   `json:"default_role_id"`
	SyncRoleOnLogin   bool     `json:"sync_role_on_login"`
	SSOLogoutEnabled  bool     `json:"sso_logout_enabled"`
	EndSessionURL     string   `json:"end_session_url,omitempty"` // read-only; populated post-discovery
	Enabled           bool     `json:"enabled"`
	HasSecret         bool     `json:"has_secret"` // signals "already set, skip re-enter"
}

func toJSON(p sso.Provider) providerJSON {
	return providerJSON{
		ID:               p.ID,
		ProviderSlug:     p.ProviderSlug,
		DisplayName:      p.DisplayName,
		IssuerURL:        p.IssuerURL,
		ClientID:         p.ClientID,
		Scopes:           p.Scopes,
		DefaultRoleID:    p.DefaultRoleID,
		SyncRoleOnLogin:  p.SyncRoleOnLogin,
		SSOLogoutEnabled: p.SSOLogoutEnabled,
		EndSessionURL:    p.EndSessionURL,
		Enabled:          p.Enabled,
		HasSecret:        true, // any row in DB has one
		// ClientSecret intentionally zero.
	}
}

// GET /api/v1/sso/providers — sso.manage
func (h *Handlers) ListSSOProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.ssoProviders.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list providers", "INTERNAL")
		return
	}
	out := make([]providerJSON, 0, len(providers))
	for _, p := range providers {
		out = append(out, toJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

// POST /api/v1/sso/providers — sso.manage
func (h *Handlers) CreateSSOProvider(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var req providerJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", "BAD_REQUEST")
		return
	}
	// Mandatory fields + server-side validation.
	if req.ProviderSlug == "" || req.DisplayName == "" || req.IssuerURL == "" ||
		req.ClientID == "" || req.ClientSecret == "" || req.DefaultRoleID == "" {
		writeError(w, http.StatusBadRequest, "missing required field", "BAD_REQUEST")
		return
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "email", "profile", "groups"}
	}
	p := sso.Provider{
		OrgID:            principal.OrgID,
		ProviderSlug:     req.ProviderSlug,
		DisplayName:      req.DisplayName,
		IssuerURL:        req.IssuerURL,
		ClientID:         req.ClientID,
		ClientSecret:     req.ClientSecret,
		Scopes:           req.Scopes,
		DefaultRoleID:    req.DefaultRoleID,
		SyncRoleOnLogin:  req.SyncRoleOnLogin,
		SSOLogoutEnabled: req.SSOLogoutEnabled,
		Enabled:          req.Enabled,
	}
	id, err := h.ssoProviders.Create(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}

	h.audit.Emit(r.Context(), /* auth.sso.provider.create event */)

	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// GET /api/v1/sso/providers/{id} — sso.manage
func (h *Handlers) GetSSOProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := h.ssoProviders.Get(r.Context(), id)
	if errors.Is(err, sso.ErrProviderNotFound) {
		writeError(w, http.StatusNotFound, "not found", "NOT_FOUND")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	writeJSON(w, http.StatusOK, toJSON(p))
}

// PATCH /api/v1/sso/providers/{id} — sso.manage
func (h *Handlers) UpdateSSOProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req providerJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", "BAD_REQUEST")
		return
	}
	current, err := h.ssoProviders.Get(r.Context(), id)
	if errors.Is(err, sso.ErrProviderNotFound) {
		writeError(w, http.StatusNotFound, "not found", "NOT_FOUND")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	// Merge: only non-zero fields in req override current.
	merged := current
	if req.DisplayName != "" { merged.DisplayName = req.DisplayName }
	if req.IssuerURL != ""   { merged.IssuerURL = req.IssuerURL }
	if req.ClientID != ""    { merged.ClientID = req.ClientID }
	if len(req.Scopes) > 0   { merged.Scopes = req.Scopes }
	if req.DefaultRoleID != "" { merged.DefaultRoleID = req.DefaultRoleID }
	// Bools are always sent (PATCH semantics): match frontend contract.
	merged.SyncRoleOnLogin = req.SyncRoleOnLogin
	merged.SSOLogoutEnabled = req.SSOLogoutEnabled
	merged.Enabled = req.Enabled

	if err := h.ssoProviders.Update(r.Context(), id, merged, req.ClientSecret); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed", "INTERNAL")
		return
	}

	h.audit.Emit(r.Context(), /* auth.sso.provider.update — redact new secret */)

	w.WriteHeader(http.StatusNoContent)
}

// DELETE /api/v1/sso/providers/{id} — sso.manage
func (h *Handlers) DeleteSSOProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.ssoProviders.Delete(r.Context(), id); err != nil {
		if errors.Is(err, sso.ErrProviderNotFound) {
			writeError(w, http.StatusNotFound, "not found", "NOT_FOUND")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}

	h.audit.Emit(r.Context(), /* auth.sso.provider.delete */)

	w.WriteHeader(http.StatusNoContent)
}
```

> Note: `h.ssoProviders` and `h.ssoMappings` are new fields on `Handlers`. Add them in `internal/controlplane/api/handlers.go` and wire up from `server.go` in Chunk 6.

- [ ] **Step 2: Tests**

File: `internal/controlplane/api/sso_providers_test.go`:

Table-driven tests for each handler:
- As `owner`: all CRUD succeed
- As `admin`: all CRUD succeed (sso.manage is granted to admin)
- As `security_engineer`: 403
- Secret never in List response (assert JSON does not contain the secret value)
- PATCH with empty client_secret preserves the encrypted value (roundtrip via Get)
- PATCH with new client_secret rotates the ciphertext

- [ ] **Step 3: Run**

Run: `go test ./internal/controlplane/api/ -run SSOProvider -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/controlplane/api/sso_providers.go internal/controlplane/api/sso_providers_test.go internal/controlplane/api/handlers.go
git commit -m "feat(sso): provider CRUD handlers (sso.manage-gated) + secret redaction"
```

### Task 4.4: Group mapping CRUD handlers

**Files:**
- Create: `internal/controlplane/api/sso_group_mappings.go`
- Create: `internal/controlplane/api/sso_group_mappings_test.go`

- [ ] **Step 1: Implement**

File: `internal/controlplane/api/sso_group_mappings.go`:

Three handlers: `ListSSOMappings`, `CreateSSOMapping`, `DeleteSSOMapping`. All gated on `sso.manage`. Validate `role_id` against `auth.roles` (reject unknown roles with 400). Validate priority range 1–10000. Reject empty or >256-char group_claim.

- [ ] **Step 2: Tests**

Cover: upsert semantics (POST with existing group updates role+priority), list returns ordered by (priority ASC, role ASC), RLS isolation.

- [ ] **Step 3: Commit**

```bash
git add internal/controlplane/api/sso_group_mappings.go internal/controlplane/api/sso_group_mappings_test.go
git commit -m "feat(sso): group mapping CRUD handlers"
```

---

## Chunk 5: /auth/sso/start + /callback flow

### Task 5.1: Client cache

**Files:**
- Create: `internal/controlplane/sso_client_cache.go`

- [ ] **Step 1: Per-provider client cache**

The `sso.Client` constructor performs HTTP discovery — expensive to repeat per request. Cache one `sso.Client` per provider ID with a simple map + mutex. Invalidate when the provider is updated (hook from `Update` handler).

File: `internal/controlplane/sso_client_cache.go`:

```go
package controlplane

import (
	"context"
	"sync"

	"github.com/sentinelcore/sentinelcore/pkg/sso"
)

// ssoClientCache stores one *sso.Client per provider_id. Hot-reloaded
// by the provider CRUD handlers via Invalidate().
type ssoClientCache struct {
	mu      sync.RWMutex
	clients map[string]*sso.Client
}

func newSSOClientCache() *ssoClientCache {
	return &ssoClientCache{clients: map[string]*sso.Client{}}
}

// Get returns an existing client or constructs + caches a new one.
// redirectURL is the public callback URL for THIS provider (includes
// org slug + provider slug; computed once at the handler level).
func (c *ssoClientCache) Get(ctx context.Context, p sso.Provider, redirectURL string) (*sso.Client, error) {
	c.mu.RLock()
	if cl, ok := c.clients[p.ID]; ok {
		c.mu.RUnlock()
		return cl, nil
	}
	c.mu.RUnlock()

	// Construct outside the write lock to avoid blocking readers on slow discovery.
	fresh, err := sso.New(ctx, sso.Config{
		IssuerURL:    p.IssuerURL,
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       p.Scopes,
	})
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check under write lock.
	if cl, ok := c.clients[p.ID]; ok {
		return cl, nil
	}
	c.clients[p.ID] = fresh
	return fresh, nil
}

// Invalidate drops the cached client for a provider. Called by
// UpdateSSOProvider / DeleteSSOProvider so a config change takes
// effect on the next request.
func (c *ssoClientCache) Invalidate(providerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.clients, providerID)
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/controlplane/sso_client_cache.go
git commit -m "feat(sso): per-provider sso.Client cache with invalidation"
```

### Task 5.2: /start handler

**Files:**
- Create: `internal/controlplane/api/sso.go` (start handler only for now)
- Create: `internal/controlplane/api/sso_test.go`

- [ ] **Step 1: Write test for /start**

File: `internal/controlplane/api/sso_test.go`:

Test cases:
- Valid org + provider + return_to → 302 to IdP authorize URL with state/nonce/PKCE query params
- Missing org → 404
- Missing provider → 404
- Disabled provider → 404
- Malicious return_to → state stores "/dashboard" instead
- State token stored in Redis with 5m TTL

- [ ] **Step 2: Implement /start**

File: `internal/controlplane/api/sso.go`:

```go
package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sentinelcore/sentinelcore/pkg/sso"
	"github.com/sentinelcore/sentinelcore/pkg/ssostate"
)

// GET /api/v1/auth/sso/{org}/{provider}/start — public
func (h *Handlers) StartSSO(w http.ResponseWriter, r *http.Request) {
	orgSlug := r.PathValue("org")
	providerSlug := r.PathValue("provider")

	p, err := h.ssoProviders.GetByOrgSlug(r.Context(), orgSlug, providerSlug)
	if errors.Is(err, sso.ErrProviderNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}

	// Validate + default return_to.
	returnTo := r.URL.Query().Get("return_to")
	if !sso.ValidateReturnTo(returnTo) {
		returnTo = "/dashboard"
	}

	// Per-request security tokens.
	state, err := randomURLSafe(32)
	if err != nil { writeError(w, 500, "rand", "INTERNAL"); return }
	nonce, err := randomURLSafe(32)
	if err != nil { writeError(w, 500, "rand", "INTERNAL"); return }
	verifier, err := sso.GenerateVerifier()
	if err != nil { writeError(w, 500, "rand", "INTERNAL"); return }
	challenge := sso.ChallengeS256(verifier)

	// Store in Redis (single-use, 5m TTL).
	if err := h.ssoState.Put(r.Context(), state, ssostate.State{
		OrgID:        p.OrgID,
		ProviderID:   p.ID,
		PKCEVerifier: verifier,
		Nonce:        nonce,
		ReturnTo:     returnTo,
		ExpiresAt:    time.Now().Add(ssostate.DefaultTTL),
	}); err != nil {
		writeError(w, 500, "state store", "INTERNAL")
		return
	}

	// Build IdP authorize URL.
	redirectURL := h.publicBaseURL + "/api/v1/auth/sso/" + orgSlug + "/" + providerSlug + "/callback"
	client, err := h.ssoClients.Get(r.Context(), p, redirectURL)
	if err != nil {
		writeError(w, 502, "provider discovery failed", "BAD_GATEWAY")
		return
	}
	// Opportunistically cache end_session_url for logout.
	if es := client.EndSessionURL(); es != "" && p.EndSessionURL == "" {
		_ = h.ssoProviders.UpdateEndSessionURL(r.Context(), p.ID, es)
	}

	authURL := client.AuthorizeURL(state, nonce, challenge)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func randomURLSafe(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
```

- [ ] **Step 3: Run /start tests**

Run: `go test ./internal/controlplane/api/ -run TestStartSSO -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/controlplane/api/sso.go internal/controlplane/api/sso_test.go
git commit -m "feat(sso): /start endpoint — state+nonce+PKCE gen, 302 to IdP"
```

### Task 5.3: /callback handler

**Files:**
- Modify: `internal/controlplane/api/sso.go` (add callback)
- Modify: `internal/controlplane/api/sso_test.go`

- [ ] **Step 1: Write callback tests (table-driven)**

Test cases (all with a fake IdP via `startFakeIdP` helper):

```go
// Happy path:
//   - state valid, code valid, id_token valid, user exists → session cookie set, 302 to return_to
// State errors:
//   - state missing → 400 BAD_REQUEST
//   - state already consumed → 400 BAD_REQUEST
//   - state from different org than URL → 400 BAD_REQUEST
// Token errors:
//   - IdP rejects code → 400 BAD_REQUEST (callback_error)
//   - id_token signature bad → 400 BAD_REQUEST (claim_error)
//   - nonce mismatch → 400 BAD_REQUEST (claim_error)
//   - aud mismatch → 400 BAD_REQUEST
//   - expired id_token → 400 BAD_REQUEST
// User provisioning:
//   - user exists by external_id → logged in, no provisioning
//   - user exists by email (identity_provider='local') → SSO identity attached, logged in
//   - user doesn't exist → JIT provisioning creates row with resolved role
//   - JIT + groups match priority-1 mapping → role_id from mapping
//   - JIT + no groups → default_role from provider
//   - sync_role_on_login=true + group changed → role updated in DB
//   - sync_role_on_login=false + group changed → role unchanged
//   - SSO login for disabled user (status != 'active') → 403
// sso_login_events:
//   - success → row with outcome='success', role_granted set
//   - failure → row with outcome='claim_error' or 'callback_error' with error_code
```

- [ ] **Step 2: Implement /callback**

Add to `internal/controlplane/api/sso.go`:

```go
// GET /api/v1/auth/sso/{org}/{provider}/callback — public
func (h *Handlers) SSOCallback(w http.ResponseWriter, r *http.Request) {
	orgSlug := r.PathValue("org")
	providerSlug := r.PathValue("provider")
	stateTok := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// Consume state (single-use).
	stored, err := h.ssoState.Take(r.Context(), stateTok)
	if errors.Is(err, ssostate.ErrStateNotFound) {
		h.logSSOEvent(r, "", "callback_error", "state_not_found", nil, nil, nil, r.RemoteAddr, r.UserAgent())
		writeError(w, http.StatusBadRequest, "state invalid or expired", "BAD_REQUEST")
		return
	}
	if err != nil {
		writeError(w, 500, "state take", "INTERNAL")
		return
	}

	// Reload the provider (state carries provider_id + org_id).
	p, err := h.ssoProviders.Get(r.Context(), stored.ProviderID)
	if err != nil {
		writeError(w, 500, "provider lookup", "INTERNAL")
		return
	}
	// Wrong-tenant check: URL org slug must match state's org.
	if p.ProviderSlug != providerSlug {
		h.logSSOEvent(r, p.ID, "callback_error", "provider_mismatch", nil, nil, nil, r.RemoteAddr, r.UserAgent())
		writeError(w, http.StatusBadRequest, "state/provider mismatch", "BAD_REQUEST")
		return
	}
	if !providerOrgMatchesURL(r.Context(), h.pool, p.OrgID, orgSlug) {
		h.logSSOEvent(r, p.ID, "callback_error", "org_mismatch", nil, nil, nil, r.RemoteAddr, r.UserAgent())
		writeError(w, http.StatusBadRequest, "state/org mismatch", "BAD_REQUEST")
		return
	}

	// Token exchange.
	redirectURL := h.publicBaseURL + "/api/v1/auth/sso/" + orgSlug + "/" + providerSlug + "/callback"
	client, err := h.ssoClients.Get(r.Context(), p, redirectURL)
	if err != nil {
		h.logSSOEvent(r, p.ID, "callback_error", "discovery_failed", nil, nil, nil, r.RemoteAddr, r.UserAgent())
		writeError(w, 502, "provider discovery", "BAD_GATEWAY")
		return
	}
	rawIDToken, err := client.Exchange(r.Context(), code, stored.PKCEVerifier)
	if err != nil {
		h.logSSOEvent(r, p.ID, "callback_error", "code_exchange_failed", nil, nil, nil, r.RemoteAddr, r.UserAgent())
		writeError(w, http.StatusBadRequest, "code exchange failed", "BAD_REQUEST")
		return
	}

	// Verify id_token.
	claims, err := client.VerifyIDToken(r.Context(), rawIDToken, stored.Nonce)
	if err != nil {
		code := "verify_failed"
		switch {
		case errors.Is(err, sso.ErrNonceMismatch):  code = "nonce_mismatch"
		case errors.Is(err, sso.ErrAudMismatch):    code = "aud_mismatch"
		case errors.Is(err, sso.ErrIssuerMismatch): code = "iss_mismatch"
		case errors.Is(err, sso.ErrTokenExpired):   code = "token_expired"
		case errors.Is(err, sso.ErrClaimsMalformed): code = "claims_malformed"
		}
		h.logSSOEvent(r, p.ID, "claim_error", code, nil, nil, nil, r.RemoteAddr, r.UserAgent())
		writeError(w, http.StatusBadRequest, "id_token verification failed", "BAD_REQUEST")
		return
	}
	if claims.Sub == "" || claims.Email == "" {
		h.logSSOEvent(r, p.ID, "claim_error", "missing_required_claim", &claims.Sub, &claims.Email, nil, r.RemoteAddr, r.UserAgent())
		writeError(w, http.StatusBadRequest, "id_token missing sub or email", "BAD_REQUEST")
		return
	}

	// JIT / lookup flow.
	mappings, err := h.ssoMappings.ListForResolver(r.Context(), p.ID)
	if err != nil {
		writeError(w, 500, "mapping load", "INTERNAL")
		return
	}
	resolvedRole, _ := sso.ResolveRole(claims.Groups, mappings, p.DefaultRoleID)

	userID, createdJIT, err := h.resolveOrProvisionSSOUser(r.Context(),
		p.OrgID, p.ProviderSlug, claims, resolvedRole, p.SyncRoleOnLogin)
	if err != nil {
		h.logSSOEvent(r, p.ID, "user_error", "provision_failed", &claims.Sub, &claims.Email, &resolvedRole, r.RemoteAddr, r.UserAgent())
		writeError(w, 500, "user provision failed", "INTERNAL")
		return
	}

	// Mint session (reuses existing pkg/auth helpers + Phase 1 RBAC cache).
	tokens, err := h.auth.IssueSession(r.Context(), userID, p.OrgID, resolvedRole)
	if err != nil {
		writeError(w, 500, "session issue", "INTERNAL")
		return
	}
	h.setAuthCookies(w, tokens)

	// Audit + diagnostics.
	h.audit.Emit(r.Context(), audit.AuditEvent{
		ActorType: "user", ActorID: userID,
		Action: "auth.sso.login",
		OrgID: p.OrgID, Result: "success",
		Details: map[string]any{
			"provider_slug":  p.ProviderSlug,
			"external_id":    claims.Sub,
			"jit_created":    createdJIT,
			"role_granted":   resolvedRole,
			"sync_role":      p.SyncRoleOnLogin,
		},
	})
	h.logSSOEvent(r, p.ID, "success", "", &claims.Sub, &claims.Email, &resolvedRole, r.RemoteAddr, r.UserAgent())

	http.Redirect(w, r, stored.ReturnTo, http.StatusFound)
}

// resolveOrProvisionSSOUser runs the spec's lookup chain:
//  1. (org_id, identity_provider, external_id) exact match
//  2. Fallback (org_id, email) — attach SSO identity to existing local user
//  3. JIT INSERT with resolved role
// Returns (user_id, createdJIT=true if inserted, error).
// If sync_role_on_login and the user's current role != resolvedRole, UPDATE.
// Runs within a single transaction so the (org_id, email) unique constraint
// + INSERT...ON CONFLICT path collapses the user-creation race.
func (h *Handlers) resolveOrProvisionSSOUser(
	ctx context.Context, orgID, providerSlug string,
	claims *sso.Claims, resolvedRole string, syncRole bool,
) (userID string, created bool, err error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil { return "", false, err }
	defer tx.Rollback(ctx)
	_, _ = tx.Exec(ctx, `SET LOCAL app.current_org_id = $1`, orgID)

	// Step 1: (org, provider, external_id).
	var (
		id string
		existingRole string
		existingProvider string
		status string
	)
	err = tx.QueryRow(ctx, `
		SELECT id::text, role, identity_provider, status FROM core.users
		WHERE org_id = $1 AND identity_provider = $2 AND external_id = $3
	`, orgID, providerSlug, claims.Sub).Scan(&id, &existingRole, &existingProvider, &status)
	switch {
	case err == nil:
		// Found by external_id.
		if status != "active" {
			return "", false, fmt.Errorf("user %s is %s", id, status)
		}
		if syncRole && existingRole != resolvedRole {
			if _, err := tx.Exec(ctx, `UPDATE core.users SET role = $1 WHERE id = $2`, resolvedRole, id); err != nil {
				return "", false, err
			}
		}
		return id, false, tx.Commit(ctx)
	case !errors.Is(err, pgx.ErrNoRows):
		return "", false, err
	}

	// Step 2: fallback by (org, email).
	err = tx.QueryRow(ctx, `
		SELECT id::text, role, identity_provider, status FROM core.users
		WHERE org_id = $1 AND email = $2
	`, orgID, claims.Email).Scan(&id, &existingRole, &existingProvider, &status)
	switch {
	case err == nil:
		if status != "active" {
			return "", false, fmt.Errorf("user %s is %s", id, status)
		}
		// Attach SSO identity if currently local.
		if existingProvider == "local" || existingProvider == "" {
			if _, err := tx.Exec(ctx,
				`UPDATE core.users SET identity_provider = $1, external_id = $2 WHERE id = $3`,
				providerSlug, claims.Sub, id); err != nil {
				return "", false, err
			}
		}
		if syncRole && existingRole != resolvedRole {
			if _, err := tx.Exec(ctx, `UPDATE core.users SET role = $1 WHERE id = $2`, resolvedRole, id); err != nil {
				return "", false, err
			}
		}
		return id, false, tx.Commit(ctx)
	case !errors.Is(err, pgx.ErrNoRows):
		return "", false, err
	}

	// Step 3: JIT insert with ON CONFLICT for race safety.
	err = tx.QueryRow(ctx, `
		INSERT INTO core.users (
		    org_id, email, display_name, role, status,
		    identity_provider, external_id, password_hash
		) VALUES ($1, $2, $3, $4, 'active', $5, $6, NULL)
		ON CONFLICT (org_id, email) DO UPDATE
		    SET identity_provider = EXCLUDED.identity_provider,
		        external_id = EXCLUDED.external_id
		RETURNING id::text
	`, orgID, claims.Email, claims.Name, resolvedRole, providerSlug, claims.Sub).Scan(&id)
	if err != nil {
		return "", false, err
	}
	return id, true, tx.Commit(ctx)
}
```

- [ ] **Step 3: Implement logSSOEvent helper**

```go
// logSSOEvent writes a diagnostic row into auth.sso_login_events.
// Claims are redacted: any value longer than 64 chars is truncated,
// and keys matching regex (?i)(secret|token|password|key|hash) are removed.
func (h *Handlers) logSSOEvent(r *http.Request, providerID, outcome, errCode string,
	externalID, email, roleGranted *string, ip, ua string) {
	// ... implementation
}
```

- [ ] **Step 4: Run all SSO tests**

Run: `go test ./internal/controlplane/api/ -run SSO -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controlplane/api/sso.go internal/controlplane/api/sso_test.go
git commit -m "feat(sso): /callback endpoint — state check, id_token verify, JIT provisioning"
```

### Task 5.4: /auth/sso/enabled + login page integration

**Files:**
- Modify: `internal/controlplane/api/sso.go`
- Modify: `internal/controlplane/api/auth.go`

- [ ] **Step 1: Add public "enabled providers" endpoint**

Public endpoint used by the login page to render "Sign in with X" buttons:

```go
// GET /api/v1/auth/sso/enabled?org=<slug> — public
// Returns [{provider_slug, display_name, start_url}] for enabled providers
// of the given org. Does NOT reveal issuer_url / client_id (reconnaissance
// surface minimisation — an attacker shouldn't be able to enumerate
// which IdP a tenant uses without a valid session).
func (h *Handlers) EnabledSSOProviders(w http.ResponseWriter, r *http.Request) {
	orgSlug := r.URL.Query().Get("org")
	if orgSlug == "" {
		writeError(w, 400, "missing org", "BAD_REQUEST")
		return
	}
	providers, err := h.ssoProviders.ListEnabledPublicByOrgSlug(r.Context(), orgSlug)
	// Store method: SELECT provider_slug, display_name FROM auth.oidc_providers
	//   JOIN core.organizations o ON o.id = oidc_providers.org_id
	//   WHERE o.slug = $1 AND enabled = true
	if err != nil {
		writeJSON(w, 200, map[string]any{"providers": []any{}}) // fail-open: empty list
		return
	}
	out := make([]map[string]any, 0, len(providers))
	for _, p := range providers {
		out = append(out, map[string]any{
			"provider_slug": p.ProviderSlug,
			"display_name":  p.DisplayName,
			"start_url":     "/api/v1/auth/sso/" + orgSlug + "/" + p.ProviderSlug + "/start",
		})
	}
	writeJSON(w, 200, map[string]any{"providers": out})
}
```

- [ ] **Step 2: Reject password login for SSO-only users**

Modify `internal/controlplane/api/auth.go`'s `Login` handler. After the row is found, check:

```go
// SSO-only users (password_hash IS NULL) cannot use password login.
// Return USE_SSO with provider slug(s) so the UI can redirect them to
// the /start endpoint.
if passwordHash == "" {
	// Fetch enabled providers for this user's org to suggest.
	providers, _ := h.ssoProviders.ListEnabledForOrg(r.Context(), orgID)
	providerSlugs := make([]string, 0, len(providers))
	for _, p := range providers {
		providerSlugs = append(providerSlugs, p.ProviderSlug)
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":         "use SSO to sign in",
		"code":          "USE_SSO",
		"providers":     providerSlugs,
	})
	return
}
```

- [ ] **Step 3: Tests**

Cover:
- Password login for SSO-only user → 401 USE_SSO with provider list
- Password login for mixed-mode user (password + external_id set) → 200 (existing behavior preserved)
- `/auth/sso/enabled?org=foo` for org with no providers → `{providers: []}`
- `/auth/sso/enabled?org=foo` with 2 enabled + 1 disabled → exactly 2 entries

- [ ] **Step 4: Commit**

```bash
git add internal/controlplane/api/sso.go internal/controlplane/api/auth.go internal/controlplane/api/auth_test.go
git commit -m "feat(sso): public /auth/sso/enabled + password-login USE_SSO rejection"
```

---

## Chunk 6: Server wiring

### Task 6.1: Register routes

**Files:**
- Modify: `internal/controlplane/server.go`

- [ ] **Step 1: Inject SSO stores + client cache on Handlers**

Add fields on `api.Handlers`:

```go
type Handlers struct {
    // ... existing fields ...
    ssoProviders   *sso.ProviderStore
    ssoMappings    *sso.MappingStore
    ssoState       *ssostate.Store
    ssoClients     *ssoClientCache
    publicBaseURL  string   // e.g. https://sentinelcore.example.com
}
```

Wire from server constructor:

```go
h.ssoProviders = sso.NewProviderStore(pool, crypto)
h.ssoMappings = sso.NewMappingStore(pool)
h.ssoState = ssostate.New(redisClient)
h.ssoClients = newSSOClientCache()
h.publicBaseURL = cfg.PublicBaseURL // from env var PUBLIC_BASE_URL
```

- [ ] **Step 2: Register 10 routes**

In `routes.go`'s RegisterRoutes function, with correct permission gating:

```go
// Public (no auth):
mux.Handle("GET /api/v1/auth/sso/{org}/{provider}/start",    h.StartSSO)
mux.Handle("GET /api/v1/auth/sso/{org}/{provider}/callback", h.SSOCallback)
mux.Handle("GET /api/v1/auth/sso/enabled",                   h.EnabledSSOProviders)

// Authenticated, no permission required:
mux.Handle("POST /api/v1/auth/sso/logout",                   auth.RequireAuth(h.SSOLogout))

// Admin-only (sso.manage):
mux.Handle("GET /api/v1/sso/providers",              auth.RequirePermission("sso.manage")(h.ListSSOProviders))
mux.Handle("POST /api/v1/sso/providers",             auth.RequirePermission("sso.manage")(h.CreateSSOProvider))
mux.Handle("GET /api/v1/sso/providers/{id}",         auth.RequirePermission("sso.manage")(h.GetSSOProvider))
mux.Handle("PATCH /api/v1/sso/providers/{id}",       auth.RequirePermission("sso.manage")(h.UpdateSSOProvider))
mux.Handle("DELETE /api/v1/sso/providers/{id}",      auth.RequirePermission("sso.manage")(h.DeleteSSOProvider))

mux.Handle("GET /api/v1/sso/providers/{id}/mappings",                auth.RequirePermission("sso.manage")(h.ListSSOMappings))
mux.Handle("POST /api/v1/sso/providers/{id}/mappings",               auth.RequirePermission("sso.manage")(h.CreateSSOMapping))
mux.Handle("DELETE /api/v1/sso/providers/{id}/mappings/{mapping_id}", auth.RequirePermission("sso.manage")(h.DeleteSSOMapping))

mux.Handle("GET /api/v1/sso/providers/{id}/history", auth.RequirePermission("sso.manage")(h.SSOLoginHistory))
```

- [ ] **Step 3: Hook cache invalidation into Update/Delete**

In `UpdateSSOProvider` and `DeleteSSOProvider`, call `h.ssoClients.Invalidate(id)` after the DB mutation succeeds.

- [ ] **Step 4: Integration test — wire through to real server**

Run: `go test ./internal/controlplane/ -run TestSSORoutes -v`
Expected: PASS. All 10 routes reachable; permission gating enforced.

- [ ] **Step 5: Commit**

```bash
git add internal/controlplane/server.go internal/controlplane/routes.go
git commit -m "feat(sso): wire SSO stores, client cache, and register 10 routes"
```

### Task 6.2: SSO logout endpoint

**Files:**
- Modify: `internal/controlplane/api/sso.go`

- [ ] **Step 1: Implement**

```go
// POST /api/v1/auth/sso/logout — authenticated
//
// Unlike /auth/logout (local only), this endpoint also redirects the
// user to their IdP's end_session_endpoint so their IdP session ends.
// Body: { "provider_id": "..." } — required; some users may have used
// password login and not need IdP logout.
func (h *Handlers) SSOLogout(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var req struct {
		ProviderID string `json:"provider_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	// Local logout first.
	if err := h.auth.RevokeSession(r.Context(), principal.JTI); err != nil {
		// ... log but don't block IdP logout
	}
	h.clearAuthCookies(w)

	if req.ProviderID == "" {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}

	p, err := h.ssoProviders.Get(r.Context(), req.ProviderID)
	if err != nil || !p.SSOLogoutEnabled || p.EndSessionURL == "" {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}

	// 302 to IdP end_session with id_token_hint + post_logout_redirect_uri.
	// We don't have the id_token anymore (we discarded it) — many IdPs
	// accept end_session without it, but some (Keycloak) require it.
	// For v1 we send without id_token_hint and document the known limitation.
	endURL := p.EndSessionURL + "?post_logout_redirect_uri=" + url.QueryEscape(h.publicBaseURL+"/login")
	writeJSON(w, 200, map[string]any{"redirect": endURL})
}
```

- [ ] **Step 2: Test**

- As user who logged in via SSO, call /sso/logout with provider_id → local JTI revoked + response contains end_session redirect URL.
- As user who logged in via password, call /sso/logout without provider_id → local logout only.

- [ ] **Step 3: Commit**

```bash
git add internal/controlplane/api/sso.go internal/controlplane/api/sso_test.go
git commit -m "feat(sso): optional full SSO logout via end_session_endpoint"
```

---

## Chunk 7: Frontend

### Task 7.1: API client + hooks

**Files:**
- Modify: `web/lib/api.ts`
- Modify: `web/lib/hooks.ts`

- [ ] **Step 1: Add SSO types + API methods**

In `web/lib/api.ts`:

```typescript
export type SSOProvider = {
  id: string;
  provider_slug: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  scopes: string[];
  default_role_id: string;
  sync_role_on_login: boolean;
  sso_logout_enabled: boolean;
  end_session_url?: string;
  enabled: boolean;
  has_secret: boolean; // true once set
};

export type SSOGroupMapping = {
  id: string;
  group_claim: string;
  role_id: string;
  priority: number;
};

export const api = {
  // ... existing ...
  sso: {
    list: () => fetch("/api/v1/sso/providers").then(j<{ providers: SSOProvider[] }>),
    get:  (id: string) => fetch(`/api/v1/sso/providers/${id}`).then(j<SSOProvider>),
    create: (p: Partial<SSOProvider> & { client_secret: string }) =>
      fetchJSON("/api/v1/sso/providers", "POST", p),
    update: (id: string, patch: Partial<SSOProvider> & { client_secret?: string }) =>
      fetchJSON(`/api/v1/sso/providers/${id}`, "PATCH", patch),
    delete: (id: string) => fetchJSON(`/api/v1/sso/providers/${id}`, "DELETE"),
    mappings: {
      list:   (pid: string) => fetch(`/api/v1/sso/providers/${pid}/mappings`).then(j<{ mappings: SSOGroupMapping[] }>),
      create: (pid: string, m: Omit<SSOGroupMapping, "id">) => fetchJSON(`/api/v1/sso/providers/${pid}/mappings`, "POST", m),
      delete: (pid: string, mid: string) => fetchJSON(`/api/v1/sso/providers/${pid}/mappings/${mid}`, "DELETE"),
    },
    history: (pid: string) => fetch(`/api/v1/sso/providers/${pid}/history`).then(j<{ events: SSOLoginEvent[] }>),
    enabled: (orgSlug: string) =>
      fetch(`/api/v1/auth/sso/enabled?org=${encodeURIComponent(orgSlug)}`).then(j<{ providers: {provider_slug: string; display_name: string; start_url: string}[] }>),
    ssoLogout: (providerID?: string) => fetchJSON("/api/v1/auth/sso/logout", "POST", { provider_id: providerID }),
  },
};
```

- [ ] **Step 2: Add hooks**

In `web/lib/hooks.ts`:

```typescript
export function useSSOProviders() { return useQuery(["sso.providers"], api.sso.list); }
export function useSSOProvider(id: string) { return useQuery(["sso.providers", id], () => api.sso.get(id), { enabled: !!id }); }
export function useSSOMappings(providerID: string) { return useQuery(["sso.mappings", providerID], () => api.sso.mappings.list(providerID), { enabled: !!providerID }); }
export function useSSOHistory(providerID: string) { return useQuery(["sso.history", providerID], () => api.sso.history(providerID), { enabled: !!providerID }); }
export function useEnabledSSOProviders(orgSlug: string) {
  return useQuery(["sso.enabled", orgSlug], () => api.sso.enabled(orgSlug), { enabled: !!orgSlug, staleTime: 60_000 });
}
```

- [ ] **Step 3: Commit**

```bash
git add web/lib/api.ts web/lib/hooks.ts
git commit -m "feat(sso): frontend API client + hooks"
```

### Task 7.2: Login page integration

**Files:**
- Modify: `web/app/login/page.tsx`

- [ ] **Step 1: Render SSO buttons**

Below the existing email/password form, render a `Sign in with {display_name}` button per enabled provider. On click: `window.location.href = provider.start_url + '?return_to=' + encodeURIComponent(returnTo)`.

Only render buttons if the user has typed their email, and the org slug is derivable from their email domain (or from a URL query param `?org=foo`).

- [ ] **Step 2: Handle USE_SSO error from password login**

If `/auth/login` returns 401 with `code: "USE_SSO"`, show a toast "Your account uses SSO — click Sign in with X below" and highlight the corresponding button.

- [ ] **Step 3: Commit**

```bash
git add web/app/login/page.tsx
git commit -m "feat(sso): login page — SSO buttons + USE_SSO error handling"
```

### Task 7.3: Settings page — provider list + form

**Files:**
- Create: `web/app/settings/sso/page.tsx`
- Create: `web/app/settings/sso/new/page.tsx`
- Create: `web/app/settings/sso/[provider]/page.tsx` (edit)

- [ ] **Step 1: Provider list page**

`/settings/sso` renders a table: `Provider | Status | Default Role | Actions`. Empty state: "No SSO providers configured. Add one to let your team sign in with Azure AD, Okta, or Keycloak." CTA → `/settings/sso/new`. Each row has an enable/disable toggle + edit/delete buttons. Deleting requires confirm dialog.

Gate the page: if the logged-in user doesn't have `sso.manage`, render the standard 403 layout. (Use the Phase 1 `<Can perm="sso.manage">` wrapper.)

- [ ] **Step 2: New/edit form**

Form fields: Provider Slug (URL-safe, disabled on edit), Display Name, Issuer URL (with live "Test Discovery" button that hits `GET {issuer}/.well-known/openid-configuration` client-side and shows parsed issuer + token endpoint), Client ID, Client Secret (password field, placeholder "●●●●●●●●" with "change" link when `has_secret && !editing_secret`), Scopes (chip input with defaults), Default Role (dropdown populated from `/auth/me`'s `roles` catalog), checkboxes: `sync_role_on_login`, `sso_logout_enabled`, `enabled`.

Cancel/Save buttons. Save: POST or PATCH. On success, toast "Provider saved" + redirect to list.

- [ ] **Step 3: Edit page also embeds the mapping editor inline**

On the edit page, a second card labeled "Group → Role Mappings" shows the list + add form. Adding a mapping: group name (text), role (dropdown), priority (number input, default 100).

- [ ] **Step 4: Tests (Playwright/Vitest)**

- New form: required fields prevent submit
- Test discovery button shows issuer on success, error on HTTP 404
- Edit form: leaving secret blank preserves it (round-trip)
- Delete: confirm dialog, then row removed

- [ ] **Step 5: Commit**

```bash
git add web/app/settings/sso/
git commit -m "feat(sso): settings UI — provider list, add/edit form, group mappings"
```

### Task 7.4: History panel

**Files:**
- Modify: `web/app/settings/sso/[provider]/page.tsx`

- [ ] **Step 1: Render history**

Third card on the edit page: "Recent login attempts (last 50)". Columns: Time, Email (or `(unknown)`), Outcome, Error Code. Click-to-expand row shows redacted claim payload as `<pre>`.

- [ ] **Step 2: Commit**

```bash
git add web/app/settings/sso/[provider]/page.tsx
git commit -m "feat(sso): history panel showing last 50 login attempts"
```

---

## Chunk 8: End-to-end verification

### Task 8.1: Staging Keycloak smoke test

- [ ] **Step 1: Spin up Keycloak locally**

```bash
cd deploy/docker-compose
# Add keycloak service to docker-compose.dev.yml (one-off, not committed):
# docker run --rm -p 8180:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
#   -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.0 start-dev
```

In Keycloak admin UI (http://localhost:8180):
1. Create realm `sc-test`
2. Create client `sentinelcore`, type `OpenID Connect`, `Standard flow` enabled
3. Valid redirect URIs: `http://localhost:8080/api/v1/auth/sso/default/keycloak/callback`
4. Create a client scope `groups` mapping the user's groups to `groups` claim
5. Add mapper so `groups` claim is in the id_token
6. Create groups: `admins`, `devs`
7. Create user `alice@example.com` with password `test` and add to `admins`

- [ ] **Step 2: Configure provider in SentinelCore**

Via settings UI:
- Provider slug: `keycloak`
- Issuer URL: `http://localhost:8180/realms/sc-test`
- Client ID: `sentinelcore`
- Client secret: (copy from Keycloak)
- Default role: `developer`

Add group mapping: `admins` → `admin`, priority 1.

- [ ] **Step 3: End-to-end login**

```bash
# Browser flow: visit http://localhost:8080/login?org=default
# Click "Sign in with Keycloak"
# Enter alice@example.com / test
# Verify: redirect to /dashboard, session cookie set, /auth/me shows role=admin
```

- [ ] **Step 4: Verify JIT + history**

```bash
psql "$DATABASE_URL" -c "SELECT email, identity_provider, external_id, role FROM core.users WHERE email = 'alice@example.com';"
# Expected: identity_provider=keycloak, external_id=<alice's sub>, role=admin, password_hash=NULL

psql "$DATABASE_URL" -c "SELECT outcome, error_code, role_granted FROM auth.sso_login_events ORDER BY occurred_at DESC LIMIT 5;"
# Expected: top row outcome=success, role_granted=admin
```

- [ ] **Step 5: Negative tests**

- Login as `alice`, then try password login with `alice@example.com` + any password → 401 USE_SSO
- Remove `alice` from `admins` group, re-login with `sync_role_on_login=true` → `/auth/me` shows role=developer
- Set provider `enabled=false`, visit /login → button disappears

- [ ] **Step 6: Commit smoke doc**

```bash
git add docs/sso-keycloak-smoke.md   # Step-by-step guide for ops
git commit -m "docs(sso): Keycloak smoke-test runbook"
```

### Task 8.2: Azure AD + Okta smoke tests (manual, document results)

- [ ] **Step 1: Azure AD tenant test**

Set up a test Entra tenant, register an app, configure group claims, verify end-to-end login works and group→role mapping resolves.

- [ ] **Step 2: Okta dev tenant test**

Same for Okta. Document any provider-specific issues (e.g. Okta's group claim format differs from Azure's).

- [ ] **Step 3: Record findings**

Append notes to `docs/sso-provider-specifics.md` for future operators.

- [ ] **Step 4: Commit**

```bash
git add docs/sso-provider-specifics.md
git commit -m "docs(sso): provider-specific notes — Azure AD, Okta, Keycloak"
```

### Task 8.3: Security tests

- [ ] **Step 1: Fuzz state/nonce tampering**

Table-driven integration test that mutates each query param of the callback URL and asserts 400 without session creation:
- state: missing, expired, replayed (use twice), cross-org (valid state from org A on org B's URL)
- code: missing, invalid (makes IdP reject)
- id_token: signature stripped, aud changed, nonce stripped, exp in past

- [ ] **Step 2: Concurrent callback test**

Fire 10 concurrent callback requests with the SAME state token. Assert: exactly 1 succeeds, other 9 all get `state not found`.

- [ ] **Step 3: Open-redirect regression**

For each bad `return_to` in `ValidateReturnTo` test table, verify `/start` stores `/dashboard` not the attacker-supplied value, and the final redirect lands on `/dashboard`.

- [ ] **Step 4: Commit**

```bash
git add internal/controlplane/api/sso_security_test.go
git commit -m "test(sso): security suite — state tampering, concurrent callback, open-redirect"
```

### Task 8.4: Full authz matrix regression

- [ ] **Step 1: Re-run Phase 1's full authz matrix**

```bash
go test ./internal/controlplane/api/ -run TestFullAuthzMatrix -v
```

Expected: PASS. Phase 3 added 11 new routes — verify each is gated correctly:
- 3 public routes (start/callback/enabled): reachable without auth
- 1 authenticated-only (sso/logout): 401 without token
- 7 sso.manage routes: 403 for non-owner/admin roles

- [ ] **Step 2: Commit any matrix test updates**

```bash
git add internal/controlplane/api/authz_matrix_test.go
git commit -m "test(sso): add 11 SSO routes to full authz matrix"
```

---

## Verification Checklist

Before tagging Phase 3 complete, every item here must pass:

- [ ] Three migrations applied cleanly in staging + production
- [ ] `\d auth.oidc_providers` shows all 14 columns + RLS + CHECK constraints
- [ ] `\d auth.oidc_group_mappings` shows RLS + UNIQUE + priority constraint
- [ ] `auth.sso_login_events` cap trigger keeps rows ≤ 500 per provider
- [ ] `pkg/sso` package: all tests pass, coverage ≥85% on `client.go` + `groups.go`
- [ ] `pkg/ssostate` roundtrip + single-use + expiry tests pass
- [ ] PKCE verifier matches RFC 7636 appendix B test vector
- [ ] `ValidateReturnTo` rejects all 15 malicious inputs
- [ ] Provider CRUD: secret never in List response, Update preserves secret if empty
- [ ] `/auth/sso/{org}/{provider}/start` returns 302 to IdP with correct query params
- [ ] `/auth/sso/{org}/{provider}/callback` happy path end-to-end against fake IdP
- [ ] `/auth/sso/enabled?org=foo` returns only enabled providers
- [ ] Password `/auth/login` for SSO-only user returns 401 USE_SSO with provider list
- [ ] JIT provisioning creates user with `password_hash IS NULL`, correct role
- [ ] Email-fallback attaches SSO identity to existing local user (no duplicate)
- [ ] `sync_role_on_login=true` updates role on next login when groups change
- [ ] `sync_role_on_login=false` preserves role even when groups change
- [ ] `auth.sso.login` audit event fires with jit_created flag + role_granted
- [ ] `sso_login_events` row per attempt, claims redacted
- [ ] Client cache hit after first Get; Update invalidates cache
- [ ] `/sso/providers/{id}/history` returns last 50 events
- [ ] Staging Keycloak end-to-end login works
- [ ] Staging Azure AD end-to-end login works
- [ ] Staging Okta end-to-end login works
- [ ] Concurrent callback race: exactly 1 of 10 wins, 9 rejected
- [ ] Open-redirect test: all 15 bad return_to values land on /dashboard
- [ ] Full authz matrix test pass (11 new routes)
- [ ] Settings UI: provider form, mapping editor, history panel all render
- [ ] Login page: SSO buttons appear per enabled provider
- [ ] `go build ./...` zero warnings; `go test ./... -count=1` all pass
- [ ] `go vet ./... && golangci-lint run` clean
- [ ] All commits build individually (bisect-safe)
- [ ] Runbook committed at `docs/sso-keycloak-smoke.md`
- [ ] Provider-specifics doc committed at `docs/sso-provider-specifics.md`

---

## Deployment Sequencing

**Phase 3 has no DB data that breaks running pods on migration**, so the standard sequence applies:

1. `git pull` on production
2. Apply migrations 029, 030, 031 (three separate transactions — each is small)
3. Rolling-restart controlplane pods (they pick up the new `/sso/*` handlers; existing code-paths unchanged)
4. Deploy updated web frontend
5. Announce SSO availability to Owners

**Feature-flag path:** if ops prefer a slower rollout, gate the `/sso/*` handlers behind `org.settings.sso_enabled` (boolean column already present on `core.organizations`). Initial post-deploy state: `sso_enabled=false` for all orgs, operator toggles `true` per-tenant via an internal flag flip. This lets us catch early-adopter issues without affecting other tenants.

---

## Rollback Plan

If Phase 3 ships with a show-stopping bug:

1. Revert the binary (kubectl rollout undo / docker compose pull previous tag)
2. Leave migrations in place — they are purely additive (no existing table modified). The unused tables cost ~4 KB. Clean them up in a follow-up migration once the fix ships.

If specifically the `/auth/sso/*` endpoints are broken, set `sso_enabled=false` org-wide via:

```sql
UPDATE core.organizations SET settings = jsonb_set(settings, '{sso_enabled}', 'false');
```

Login page stops showing SSO buttons; users fall back to password. Nothing else breaks.

---

## Out of Scope (deferred to future phases)

Documented here so reviewers don't flag them:

- **SAML 2.0** — schema anticipates this via a `protocol` column that Phase 3 omits (all rows are `oidc`). Adding SAML is a follow-up; generalize the table to `auth.sso_providers` with `protocol TEXT NOT NULL DEFAULT 'oidc'`.
- **Back-channel logout** — requires a public endpoint that verifies signed logout tokens. Noted in spec.
- **IdP-initiated login** — attack surface; only SP-initiated in v1.
- **Periodic role re-evaluation** — role is re-checked only on login, not on every request. Means IdP group changes propagate on the user's next login.
- **AES-GCM key rotation for client_secret** — `pkg/crypto/aesgcm` ciphertext has a version prefix (`enc:v1:`) precisely so a future dual-key mode can decrypt both. Implementing rotation is out of scope.

---

## Reference Skills

- @superpowers:test-driven-development — every new Go file follows TDD
- @superpowers:subagent-driven-development — execute this plan with fresh subagents per chunk, two-stage review
- @superpowers:executing-plans — fallback for single-session execution

---

## Chunk Boundaries Summary

| Chunk | Tasks | Lines (est.) | Logically self-contained |
|-------|-------|--------------|--------------------------|
| 1 | Migrations 029–031 | ~200 | Yes (pure schema, no code deps) |
| 2 | pkg/sso core (pkce, return_to, groups, client) | ~800 | Yes (pure library) |
| 3 | pkg/ssostate Redis store | ~200 | Yes |
| 4 | Provider + mapping stores + CRUD handlers | ~900 | Yes (needs Chunks 2+3) |
| 5 | /start + /callback + JIT + USE_SSO | ~700 | Yes (needs Chunks 2–4) |
| 6 | Server wiring + SSO logout | ~250 | Yes |
| 7 | Frontend (api, hooks, pages) | ~500 | Yes |
| 8 | Verification (smokes, security, matrix) | ~250 | Yes |

Total ~3,800 lines of plan; actual code delta roughly ~2,500 LOC Go + ~1,000 LOC TS.
