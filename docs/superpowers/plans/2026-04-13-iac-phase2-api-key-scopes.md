# IAC Phase 2 — API Key Scopes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce API key scopes at middleware level using the Phase 1 RBAC cache vocabulary, validate scopes at creation against the creator's permission ceiling, support service-account keys (with/without user binding), add rotation endpoint + hourly expiration sweep, implement role-downgrade auto-revoke, and ship a frontend API-keys page with scope picker and one-time plaintext display.

**Architecture:** Reuses Phase 1's `Principal.Can()` — API keys already flow through it (scopes list is checked against the required permission). This phase focuses on (1) creation-time privilege ceiling enforcement, (2) rotation flow, (3) expiration sweep in retention-worker, (4) role-downgrade trigger, (5) backfill of existing keys, (6) frontend. No new middleware layers.

**Tech Stack:** Go 1.26, PostgreSQL 16 (pgx/v5), pkg/audit (NATS), existing retention-worker for cron jobs, Next.js 16 frontend.

**Depends on:** Phase 1 RBAC plan (`docs/superpowers/plans/2026-04-13-iac-phase1-rbac-refactor.md`) must be fully deployed. Specifically: `auth.permissions` catalog, `Principal.Can()`, `rbacCache.HasPermission()`.

**Related spec:** `docs/superpowers/specs/2026-04-13-identity-access-control-design.md` (Phase 2 sections).

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `migrations/026_api_key_columns.up.sql` + `.down.sql` | Add `is_service_account`, `description`, `rotated_at`, `created_by` columns; relax `user_id` to nullable; add CHECK constraint |
| `migrations/027_api_key_proposed_scopes.up.sql` + `.down.sql` | Temporary staging column `proposed_scopes` for backfill; dropped in Phase 2 cleanup |
| `migrations/028_role_downgrade_trigger.up.sql` + `.down.sql` | `AFTER UPDATE OF role` trigger on `core.users` — auto-revokes user-owned keys exceeding new role + emits `NOTIFY user_sessions_revoke` |
| `pkg/apikeys/scope_validation.go` | `ValidateScopes(requested, creator_permissions, known_permissions) error` — privilege-ceiling check |
| `pkg/apikeys/scope_validation_test.go` | Unit tests for scope validation (unknown, escalation, identity) |
| `pkg/apikeys/rotate.go` | `Rotate(ctx, pool, keyID, orgID) (*CreateResult, error)` — atomic UPDATE, returns new plaintext |
| `pkg/apikeys/rotate_test.go` | Rotation tests (atomic replace, concurrent rotation, idempotence of old-hash failure) |
| `internal/controlplane/api/apikeys_rotate.go` | HTTP handler for `POST /api/v1/api-keys/{id}/rotate` |
| `internal/controlplane/api/apikeys_rotate_test.go` | Handler integration tests |
| `cmd/retention-worker/sweep_api_keys.go` (or extend existing) | Hourly job: `UPDATE core.api_keys SET revoked=true WHERE expires_at < now() AND revoked=false` |
| `internal/apikeys/session_revoke_listener.go` | LISTEN `user_sessions_revoke` → revoke all JTIs for the user_id in Redis |
| `cmd/migrate-api-keys/main.go` | One-shot backfill CLI: preview, write `proposed_scopes`, execute backfill per-tenant |
| `web/features/api-keys/api.ts` | API client: listKeys, createKey, rotateKey, revokeKey |
| `web/features/api-keys/hooks.ts` | React Query hooks |
| `web/features/api-keys/api-keys-table.tsx` | List view with rotate/revoke actions |
| `web/features/api-keys/create-key-dialog.tsx` | Create form with scope picker + service-account toggle |
| `web/features/api-keys/key-plaintext-modal.tsx` | One-time plaintext display modal with copy-to-clipboard + "This is the only time" warning |
| `web/features/api-keys/scope-picker.tsx` | Checkbox grid grouped by category; grays out scopes exceeding current user's ceiling |
| `web/app/(dashboard)/api-keys/page.tsx` | Route page |

### Modified files

| File | Change |
|---|---|
| `pkg/apikeys/apikeys.go` | Update `Create()` signature to accept `creatorID`, `isServiceAccount`, `description`; call `ValidateScopes()` against creator's permissions before insert; add `CreatedBy` to `Key` + `ResolvedKey` |
| `internal/controlplane/api/apikeys.go` | Extend `CreateAPIKey` handler: read creator permissions from cache, enforce `is_service_account` requires Owner/Admin, pass through to `apikeys.Create()` |
| `internal/controlplane/server.go` | Register new rotate route under the same `s.authz("api_keys.manage", ...)` pattern from Phase 1; start `session_revoke_listener` in constructor |
| `cmd/retention-worker/main.go` | Wire up the hourly API-key expiration sweep |
| `web/components/layout/sidebar.tsx` | Add "API Keys" nav item (gated by `api_keys.read`) |
| `web/components/layout/command-palette.tsx` | Add "API Keys" to Pages group |

### No changes to

- `pkg/auth/principal.go` — `Principal.Can()` already handles API keys via scopes list.
- `pkg/auth/require_permission.go` — scope enforcement is already part of the Phase 1 middleware.
- JWT issuer / validator — API keys are a separate auth path.

---

## Chunk 1: Schema Changes

### Task 1.1: Add API-key columns migration

**Files:**
- Create: `migrations/026_api_key_columns.up.sql`
- Create: `migrations/026_api_key_columns.down.sql`

- [ ] **Step 1: Write the up migration**

File: `migrations/026_api_key_columns.up.sql`:

```sql
BEGIN;

ALTER TABLE core.api_keys
    ADD COLUMN IF NOT EXISTS is_service_account BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS description         TEXT,
    ADD COLUMN IF NOT EXISTS rotated_at          TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS created_by          UUID REFERENCES core.users(id);

-- Backfill created_by = user_id for pre-existing rows (every key today is
-- user-owned by definition; service accounts didn't exist yet).
UPDATE core.api_keys SET created_by = user_id WHERE created_by IS NULL;

-- Now make user_id nullable (needed for tenant-owned service accounts).
ALTER TABLE core.api_keys ALTER COLUMN user_id DROP NOT NULL;

-- Preserve invariant: either a user owns the key, or it's a service account.
-- A NULL user_id with is_service_account=false would be an orphaned key.
ALTER TABLE core.api_keys ADD CONSTRAINT api_keys_principal_check
    CHECK (user_id IS NOT NULL OR is_service_account = true);

-- created_by must always be set; never NULL even for tenant-owned keys
-- (we always record who issued them for audit).
ALTER TABLE core.api_keys ALTER COLUMN created_by SET NOT NULL;

COMMIT;
```

- [ ] **Step 2: Write the down migration**

File: `migrations/026_api_key_columns.down.sql`:

```sql
-- WARNING: this rollback removes the columns. If any tenant-owned
-- service-account keys exist (user_id IS NULL), the down migration
-- will fail at the NOT NULL constraint restore.

BEGIN;

-- Refuse to drop user_id's NOT NULL restoration if tenant-owned keys exist.
DO $$
DECLARE
    orphan_count INT;
BEGIN
    SELECT count(*) INTO orphan_count
    FROM core.api_keys WHERE user_id IS NULL;
    IF orphan_count > 0 THEN
        RAISE EXCEPTION
            'Refusing to rollback: % tenant-owned service-account keys would be orphaned. '
            'Delete or reassign them before rolling back.', orphan_count;
    END IF;
END $$;

ALTER TABLE core.api_keys DROP CONSTRAINT IF EXISTS api_keys_principal_check;
ALTER TABLE core.api_keys ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS created_by;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS rotated_at;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS description;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS is_service_account;

COMMIT;
```

- [ ] **Step 3: Apply + verify**

Run:
```bash
psql "$DATABASE_URL" -f migrations/026_api_key_columns.up.sql
psql "$DATABASE_URL" -c "\d core.api_keys" | grep -E "created_by|is_service_account|rotated_at|description|user_id"
```
Expected: `user_id` shown as nullable; new columns present; `created_by` NOT NULL.

- [ ] **Step 4: Commit**

```bash
git add migrations/026_api_key_columns.up.sql migrations/026_api_key_columns.down.sql
git commit -m "feat(apikeys): add is_service_account, description, rotated_at, created_by columns"
```

### Task 1.2: Proposed-scopes staging column (backfill)

**Files:**
- Create: `migrations/027_api_key_proposed_scopes.up.sql`
- Create: `migrations/027_api_key_proposed_scopes.down.sql`

- [ ] **Step 1: Up migration**

File: `migrations/027_api_key_proposed_scopes.up.sql`:

```sql
BEGIN;
ALTER TABLE core.api_keys
    ADD COLUMN IF NOT EXISTS proposed_scopes TEXT[];
COMMENT ON COLUMN core.api_keys.proposed_scopes IS
    'Backfill staging: scopes the rolling backfill will assign to pre-existing '
    'keys that currently have empty scopes. NULL for keys not eligible for backfill '
    '(already have explicit scopes) or already migrated. Column is dropped in migration 029 '
    'once backfill is complete and tenants have had 30 days to react.';
COMMIT;
```

- [ ] **Step 2: Down migration**

File: `migrations/027_api_key_proposed_scopes.down.sql`:

```sql
BEGIN;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS proposed_scopes;
COMMIT;
```

- [ ] **Step 3: Apply + commit**

```bash
psql "$DATABASE_URL" -f migrations/027_api_key_proposed_scopes.up.sql
git add migrations/027_api_key_proposed_scopes.up.sql migrations/027_api_key_proposed_scopes.down.sql
git commit -m "feat(apikeys): add proposed_scopes staging column for backfill"
```

### Task 1.3: Role-downgrade auto-revoke trigger

**Files:**
- Create: `migrations/028_role_downgrade_trigger.up.sql`
- Create: `migrations/028_role_downgrade_trigger.down.sql`

- [ ] **Step 1: Up migration**

File: `migrations/028_role_downgrade_trigger.up.sql`:

```sql
-- When a user's role is downgraded, auto-revoke user-owned API keys whose
-- scopes exceed the new role's permissions. Runs in the same transaction
-- as the UPDATE OF role so there is NO window where the old role is
-- visible to other transactions while the keys still work (TOCTOU closure).
--
-- Service-account keys (is_service_account=true) are NOT revoked — that's
-- the whole point of service accounts (they outlive the creator's role).

BEGIN;

-- Small side table for events that trigger functions can't emit directly.
-- org_id is included directly (not just in details JSONB) so the drainer
-- can tenant-scope NATS emissions without JSONB parsing. Must come before
-- the trigger function since the function inserts into this table.
CREATE TABLE IF NOT EXISTS auth.pending_audit_events (
    id          BIGSERIAL PRIMARY KEY,
    org_id      UUID NOT NULL,
    event_type  TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    details     JSONB NOT NULL,
    processed   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pending_audit_events_unprocessed_idx
    ON auth.pending_audit_events (org_id, created_at) WHERE processed = false;

-- SECURITY DEFINER is required: the trigger fires under whatever session
-- triggered the UPDATE on core.users, which may or may not have
-- app.current_org_id set (an admin CLI path may not set it). The function
-- must query auth.role_permissions (global) and update core.api_keys
-- regardless of RLS on the calling session. search_path is pinned to
-- prevent search-path injection attacks (standard PG hardening).
CREATE OR REPLACE FUNCTION auth.revoke_excess_scope_keys_on_role_change()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = auth, core, pg_catalog
AS $$
DECLARE
    new_role_perms TEXT[];
    key_record RECORD;
BEGIN
    -- Only act on actual role change.
    IF NEW.role IS NOT DISTINCT FROM OLD.role THEN
        RETURN NEW;
    END IF;

    -- Load the new role's permission set.
    SELECT array_agg(permission_id) INTO new_role_perms
    FROM auth.role_permissions
    WHERE role_id = NEW.role;

    -- If the new role has no permissions (unknown role), skip to avoid
    -- revoking everything accidentally. A proper check constraint on
    -- core.users.role + the auth.roles FK (Phase 1 migration 025) already
    -- prevents unknown roles, but we belt-and-brace.
    IF new_role_perms IS NULL THEN
        RETURN NEW;
    END IF;

    -- Find user-owned keys with scopes exceeding the new role.
    -- NOTE: PostgreSQL core does NOT provide `-` (set-difference) on
    -- text[] — only the `intarray` extension provides it, and only for
    -- integer[]. So we use an EXISTS subquery to check "does the key have
    -- any scope not in new_role_perms" without the extension dependency.
    FOR key_record IN
        SELECT id, prefix FROM core.api_keys
        WHERE user_id = NEW.id
          AND is_service_account = false
          AND revoked = false
          AND array_length(scopes, 1) > 0
          AND EXISTS (
              SELECT 1
              FROM unnest(scopes) AS scope
              WHERE scope <> ALL (new_role_perms)
          )
    LOOP
        UPDATE core.api_keys
        SET revoked = true
        WHERE id = key_record.id;

        -- Emit a marker for the audit emitter (emitted from app code on
        -- COMMIT — the trigger itself can't reach NATS directly).
        -- We record the intent in a side table that the app reads post-commit.
        -- org_id is populated directly from the triggering user row so the
        -- drainer can tenant-scope the NATS emission.
        INSERT INTO auth.pending_audit_events (org_id, event_type, resource_id, details, created_at)
        VALUES (
            NEW.org_id,
            'api_key.auto_revoke',
            key_record.id::text,
            jsonb_build_object(
                'reason', 'role_downgrade',
                'prefix', key_record.prefix,
                'user_id', NEW.id,
                'org_id', NEW.org_id,
                'old_role', OLD.role,
                'new_role', NEW.role
            ),
            now()
        );
    END LOOP;

    -- Notify the session-revoke listener so it invalidates JTIs in Redis.
    -- Payload = user_id. The listener parses this and runs SREM on the
    -- session-tracking Redis key for that user.
    PERFORM pg_notify('user_sessions_revoke', NEW.id::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Ensure the function is owned by a superuser or the schema owner so
-- SECURITY DEFINER runs with appropriate privileges. In this codebase
-- migrations run as the `sentinelcore` user which owns both schemas, so
-- no explicit OWNER change is needed — but we assert it:
DO $$
BEGIN
    IF (SELECT proowner FROM pg_proc WHERE proname = 'revoke_excess_scope_keys_on_role_change') <>
       (SELECT oid FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'function owner mismatch — SECURITY DEFINER may not bypass RLS as expected';
    END IF;
END $$;

CREATE TRIGGER users_role_change_revoke_keys
    AFTER UPDATE OF role ON core.users
    FOR EACH ROW
    EXECUTE FUNCTION auth.revoke_excess_scope_keys_on_role_change();

COMMIT;
```

- [ ] **Step 2: Down migration**

File: `migrations/028_role_downgrade_trigger.down.sql`:

```sql
-- Refuse to roll back if unprocessed audit events still exist — otherwise
-- legitimate key-revocation events would be silently dropped (violates
-- the at-least-once audit delivery guarantee the up migration promises).
-- Operators who intend to accept the loss can manually truncate first.
BEGIN;
DO $$
DECLARE
    pending_count INT;
BEGIN
    SELECT COUNT(*) INTO pending_count FROM auth.pending_audit_events WHERE processed = false;
    IF pending_count > 0 THEN
        RAISE EXCEPTION 'refusing to roll back 028: % unprocessed audit events in auth.pending_audit_events. Drain the queue (wait for the controlplane drainer) or truncate manually with: DELETE FROM auth.pending_audit_events WHERE processed = false;', pending_count;
    END IF;
END $$;
DROP TRIGGER IF EXISTS users_role_change_revoke_keys ON core.users;
DROP FUNCTION IF EXISTS auth.revoke_excess_scope_keys_on_role_change();
DROP TABLE IF EXISTS auth.pending_audit_events;
COMMIT;
```

- [ ] **Step 3: Apply**

```bash
psql "$DATABASE_URL" -f migrations/028_role_downgrade_trigger.up.sql
```

- [ ] **Step 4: Manual verification**

In psql:
```sql
-- Setup: create a test user with admin role + a key with users.manage scope.
INSERT INTO core.users (id, org_id, username, email, display_name, role, password_hash)
VALUES ('11111111-2222-3333-4444-555555555555',
        (SELECT id FROM core.organizations LIMIT 1),
        'trigger-test', 'trigger-test@example.com', 'Trigger Test',
        'admin', '$2b$12$dummy');

INSERT INTO core.api_keys (id, org_id, user_id, created_by, name, prefix, key_hash,
                           scopes, is_service_account, revoked)
VALUES ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        (SELECT id FROM core.organizations LIMIT 1),
        '11111111-2222-3333-4444-555555555555',
        '11111111-2222-3333-4444-555555555555',
        'test-key', 'abcd1234', 'dummyhash',
        ARRAY['scans.run', 'api_keys.manage'], -- api_keys.manage is admin-only
        false, false);

-- Trigger: downgrade to developer (developer doesn't have api_keys.manage or scans.run).
UPDATE core.users SET role = 'developer'
WHERE id = '11111111-2222-3333-4444-555555555555';

-- Verify: key should be revoked.
SELECT revoked FROM core.api_keys WHERE id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
-- Expected: t

-- Verify: pending audit event recorded.
SELECT event_type, details FROM auth.pending_audit_events
WHERE resource_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
-- Expected: 'api_key.auto_revoke', {"reason":"role_downgrade",...}

-- Cleanup:
DELETE FROM core.api_keys WHERE id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
DELETE FROM auth.pending_audit_events WHERE resource_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
DELETE FROM core.users WHERE id = '11111111-2222-3333-4444-555555555555';
```

- [ ] **Step 5: Commit**

```bash
git add migrations/028_role_downgrade_trigger.up.sql migrations/028_role_downgrade_trigger.down.sql
git commit -m "feat(apikeys): auto-revoke user-owned keys on role downgrade (trigger + pending_audit_events)"
```

---

## Chunk 2: Scope Validation Library

### Task 2.1: ValidateScopes function

**Files:**
- Create: `pkg/apikeys/scope_validation.go`
- Create: `pkg/apikeys/scope_validation_test.go`

- [ ] **Step 1: Write the failing tests**

File: `pkg/apikeys/scope_validation_test.go`:

```go
package apikeys

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateScopes_RejectsUnknownScope(t *testing.T) {
	known := map[string]struct{}{"risks.read": {}, "scans.read": {}}
	creator := map[string]struct{}{"risks.read": {}, "scans.read": {}}

	err := ValidateScopes([]string{"risks.read", "nonsense.permission"}, creator, known)
	if err == nil {
		t.Fatal("expected error for unknown scope")
	}
	var unknown *UnknownScopeError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected UnknownScopeError, got %T: %v", err, err)
	}
	if unknown.Scope != "nonsense.permission" {
		t.Fatalf("Scope=%q, want nonsense.permission", unknown.Scope)
	}
}

func TestValidateScopes_RejectsPrivilegeEscalation(t *testing.T) {
	known := map[string]struct{}{
		"risks.read": {}, "scans.run": {}, "users.manage": {},
	}
	creator := map[string]struct{}{"risks.read": {}, "scans.run": {}}

	err := ValidateScopes([]string{"users.manage"}, creator, known)
	if err == nil {
		t.Fatal("expected escalation error")
	}
	var esc *PrivilegeEscalationError
	if !errors.As(err, &esc) {
		t.Fatalf("expected PrivilegeEscalationError, got %T: %v", err, err)
	}
	if esc.Scope != "users.manage" {
		t.Fatalf("Scope=%q, want users.manage", esc.Scope)
	}
	if !strings.Contains(err.Error(), "users.manage") {
		t.Fatalf("error message should mention the scope: %s", err)
	}
}

func TestValidateScopes_AllowsSubsetOfCreator(t *testing.T) {
	known := map[string]struct{}{
		"risks.read": {}, "scans.run": {}, "findings.read": {},
	}
	creator := map[string]struct{}{
		"risks.read": {}, "scans.run": {}, "findings.read": {},
	}

	err := ValidateScopes([]string{"risks.read", "findings.read"}, creator, known)
	if err != nil {
		t.Fatalf("subset should be allowed, got: %v", err)
	}
}

func TestValidateScopes_AllowsIdentical(t *testing.T) {
	known := map[string]struct{}{"risks.read": {}, "scans.run": {}}
	creator := map[string]struct{}{"risks.read": {}, "scans.run": {}}

	err := ValidateScopes([]string{"risks.read", "scans.run"}, creator, known)
	if err != nil {
		t.Fatalf("identical set should be allowed, got: %v", err)
	}
}

func TestValidateScopes_RejectsEmptyScopes(t *testing.T) {
	known := map[string]struct{}{"risks.read": {}}
	creator := map[string]struct{}{"risks.read": {}}

	err := ValidateScopes([]string{}, creator, known)
	if err == nil {
		t.Fatal("expected error for empty scope list")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("error should mention 'at least one', got: %s", err)
	}
}

func TestValidateScopes_RejectsDuplicates(t *testing.T) {
	known := map[string]struct{}{"risks.read": {}}
	creator := map[string]struct{}{"risks.read": {}}

	err := ValidateScopes([]string{"risks.read", "risks.read"}, creator, known)
	if err == nil {
		t.Fatal("expected error for duplicate scope")
	}
}
```

- [ ] **Step 2: Run tests (fail)**

Run: `go test ./pkg/apikeys/ -run TestValidateScopes -v`
Expected: FAIL — ValidateScopes not defined.

- [ ] **Step 3: Implement**

File: `pkg/apikeys/scope_validation.go`:

```go
package apikeys

import "fmt"

// UnknownScopeError is returned when a requested scope is not a known
// permission in the auth.permissions catalog. The UI can suggest similar
// names by fuzzy-matching against the full catalog.
type UnknownScopeError struct {
	Scope string
}

func (e *UnknownScopeError) Error() string {
	return fmt.Sprintf("unknown scope: %q", e.Scope)
}

// PrivilegeEscalationError is returned when the requested scope is not in
// the creator's own permission set. The creator cannot grant permissions
// they do not themselves possess.
type PrivilegeEscalationError struct {
	Scope string
}

func (e *PrivilegeEscalationError) Error() string {
	return fmt.Sprintf("cannot grant scope you don't have: %q", e.Scope)
}

// EmptyScopesError — sentinel for requests with no scopes. Exposed as a
// value so handlers can errors.Is() it to 400 BAD_REQUEST.
var EmptyScopesError = fmt.Errorf("scopes must contain at least one permission")

// DuplicateScopeError is returned when the requested list contains the
// same scope twice. Also triggers 400 BAD_REQUEST at the handler.
type DuplicateScopeError struct {
	Scope string
}

func (e *DuplicateScopeError) Error() string {
	return fmt.Sprintf("duplicate scope: %q", e.Scope)
}

// ValidateScopes enforces three rules on an API-key scope list:
//   1. Must contain at least one scope.
//   2. Every scope must exist in the permissions catalog (known).
//   3. Every scope must be in the creator's own permission set.
//   4. No duplicates (case-sensitive).
//
// Returns one of the typed errors above so handlers can map each to the
// correct HTTP status without string-matching.
//
// known + creator are passed as sets for O(1) lookup. Typical callers
// obtain them from the RBAC cache.
func ValidateScopes(requested []string, creator, known map[string]struct{}) error {
	if len(requested) == 0 {
		return EmptyScopesError
	}

	seen := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		if _, dup := seen[scope]; dup {
			return &DuplicateScopeError{Scope: scope}
		}
		seen[scope] = struct{}{}

		if _, ok := known[scope]; !ok {
			return &UnknownScopeError{Scope: scope}
		}
		if _, ok := creator[scope]; !ok {
			return &PrivilegeEscalationError{Scope: scope}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests (pass)**

Run: `go test ./pkg/apikeys/ -run TestValidateScopes -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/apikeys/scope_validation.go pkg/apikeys/scope_validation_test.go
git commit -m "feat(apikeys): add ValidateScopes with privilege-ceiling enforcement"
```

### Task 2.2: Wire ValidateScopes into apikeys.Create

**Files:**
- Modify: `pkg/apikeys/apikeys.go`

- [ ] **Step 1: Read current Create signature**

Run: `sed -n '80,120p' pkg/apikeys/apikeys.go`
Note: current signature is `Create(ctx, pool, orgID, userID, name, scopes, expiresAt)`.

- [ ] **Step 2: Extend signature and struct**

In `pkg/apikeys/apikeys.go`:

```go
// CreateInput bundles all parameters for key creation. Introduced in
// Phase 2 so we can add service-account + description + creator ceiling
// without a long positional parameter list.
type CreateInput struct {
	OrgID              string
	CreatedBy          string   // human who issued the key (always set)
	UserID             string   // principal the key authenticates as (empty for tenant-owned service accounts)
	Name               string
	Description        string   // optional
	Scopes             []string
	ExpiresAt          *time.Time
	IsServiceAccount   bool

	// CreatorPermissions is the full permission set of the user issuing
	// the key. Passed in (not looked up) so the policy cache isn't a
	// dependency of this package.
	CreatorPermissions map[string]struct{}

	// KnownPermissions is the full permissions catalog (set of all
	// permission ids in auth.permissions). Used to reject typos.
	KnownPermissions map[string]struct{}
}

// Create issues a new API key after validating scopes against the
// creator's permission ceiling. The raw plaintext is returned ONCE in
// CreateResult.PlainText and never stored.
func Create(ctx context.Context, pool *pgxpool.Pool, in CreateInput) (*CreateResult, error) {
	if in.OrgID == "" || in.CreatedBy == "" {
		return nil, fmt.Errorf("org_id and created_by are required")
	}
	if in.UserID == "" && !in.IsServiceAccount {
		return nil, fmt.Errorf("user_id required unless is_service_account=true")
	}

	if err := ValidateScopes(in.Scopes, in.CreatorPermissions, in.KnownPermissions); err != nil {
		return nil, err
	}

	raw := Generate()
	hash := Hash(raw)
	prefix := PrefixOf(raw)
	keyID := uuid.NewString()

	var userIDParam any
	if in.UserID != "" {
		userIDParam = in.UserID
	} else {
		userIDParam = nil
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO core.api_keys (
			id, org_id, user_id, created_by, name, description,
			prefix, key_hash, scopes, expires_at, is_service_account, revoked
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false)
	`, keyID, in.OrgID, userIDParam, in.CreatedBy, in.Name, in.Description,
		prefix, hash, in.Scopes, in.ExpiresAt, in.IsServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("insert api_key: %w", err)
	}

	return &CreateResult{
		ID:               keyID,
		PlainText:        raw,
		Prefix:           prefix,
		Name:             in.Name,
		Description:      in.Description,
		Scopes:           in.Scopes,
		ExpiresAt:        in.ExpiresAt,
		IsServiceAccount: in.IsServiceAccount,
	}, nil
}
```

Add `Description` and `IsServiceAccount` fields to `CreateResult` at the top of the file. **Explicitly verify the JSON tags** — the frontend (`web/lib/api.ts`) expects these exact keys:

```go
type CreateResult struct {
    ID               string     `json:"id"`
    PlainText        string     `json:"plaintext"`          // shown once, never stored
    Prefix           string     `json:"prefix"`
    Name             string     `json:"name"`
    Description      string     `json:"description,omitempty"`
    Scopes           []string   `json:"scopes"`
    ExpiresAt        *time.Time `json:"expires_at,omitempty"`
    IsServiceAccount bool       `json:"is_service_account"`
}
```

`json:"plaintext"` (one word, lowercase) must match the frontend contract. Add an assertion in Task 2.3 Step 4's unit test: `assert.Contains(t, body, "\"plaintext\":")` so a future rename can't silently break the UI.

**IMPORTANT — atomic commit with Task 2.3.** The old `Create(ctx, pool, orgID, userID, name, scopes, expiresAt)` signature is removed in this step, but the existing caller in `internal/controlplane/api/apikeys.go` still references it. Committing this task in isolation would leave `main` broken (breaks `git bisect`, breaks any CI "every commit builds" gate). So Task 2.2 does NOT produce a commit on its own — Steps 3–4 below only build the single package, and the commit is deferred to Task 2.3 Step 4 which stages both files together.

- [ ] **Step 3: Build (package-level only)**

Run: `go build ./pkg/apikeys/`
Expected: exit 0. (A full `go build ./...` will fail until Task 2.3 is applied — that's expected.)

- [ ] **Step 4: (no commit yet — continue to Task 2.3)**

Leave `pkg/apikeys/apikeys.go` staged but uncommitted. Proceed directly to Task 2.3. Both files will be committed together in Task 2.3 Step 4.

### Task 2.3: Update handler to pass creator + known permissions

**Files:**
- Modify: `internal/controlplane/api/apikeys.go`

- [ ] **Step 1: Read current handler**

Run: `cat internal/controlplane/api/apikeys.go`

- [ ] **Step 2: Update handler**

Replace `CreateAPIKey`:

```go
type createAPIKeyRequest struct {
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	Scopes           []string `json:"scopes"`
	ExpiresIn        string   `json:"expires_in,omitempty"` // e.g. "90d"
	IsServiceAccount bool     `json:"is_service_account,omitempty"`
}

func (h *Handlers) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHENTICATED")
		return
	}
	// Enforcement of api_keys.manage is at the middleware level.
	// This handler still needs principal to know who issued the key
	// and to compute the ceiling.

	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", "BAD_REQUEST")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required", "BAD_REQUEST")
		return
	}

	// Service-account keys require a human Owner or Admin caller.
	// Principal.Role is empty for api_key principals (spec line 58), so
	// "API-key calls API-key-create for a service account" is rejected
	// here to prevent key-chain privilege laundering.
	if req.IsServiceAccount {
		if principal.Kind == "api_key" {
			writeError(w, http.StatusForbidden,
				"service-account keys must be created by a human user, not another API key",
				"FORBIDDEN")
			return
		}
		if principal.Role != "owner" && principal.Role != "admin" {
			writeError(w, http.StatusForbidden,
				"service-account keys require owner or admin role",
				"FORBIDDEN")
			return
		}
	}

	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		d, err := parseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_in: "+err.Error(), "BAD_REQUEST")
			return
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	// Load creator's permissions + full catalog from the RBAC cache.
	// h.RBACCache is set on Handlers during server initialization (Phase 1).
	//
	// Two code paths:
	//   - User-backed caller: ceiling = their role's permissions.
	//   - API-key-backed caller: principal.Role is empty (spec line 58);
	//     ceiling = the calling key's scopes. This preserves the
	//     ceiling-under-ceiling invariant: a key with {a,b} cannot mint
	//     another key with {c} because c ∉ {a,b}.
	creatorPerms := make(map[string]struct{})
	switch principal.Kind {
	case "api_key":
		for _, s := range principal.Scopes {
			creatorPerms[s] = struct{}{}
		}
	default: // "user" or empty
		for _, p := range h.RBACCache.PermissionsFor(principal.Role) {
			creatorPerms[p] = struct{}{}
		}
	}
	knownPerms := make(map[string]struct{})
	for _, p := range h.RBACCache.AllPermissions() {
		knownPerms[p] = struct{}{}
	}

	// Determine user_id: empty for tenant-owned service accounts.
	userID := principal.UserID
	if req.IsServiceAccount {
		// Tenant-owned service accounts have user_id = NULL. The spec
		// also supports service-owned (user_id set + is_service_account=true)
		// — for now we default service-account creations to tenant-owned.
		// Future: add request.ServiceOwnerUserID to distinguish.
		userID = ""
	}

	result, err := apikeys.Create(r.Context(), h.pool, apikeys.CreateInput{
		OrgID:              principal.OrgID,
		CreatedBy:          principal.UserID,
		UserID:             userID,
		Name:               req.Name,
		Description:        req.Description,
		Scopes:             req.Scopes,
		ExpiresAt:          expiresAt,
		IsServiceAccount:   req.IsServiceAccount,
		CreatorPermissions: creatorPerms,
		KnownPermissions:   knownPerms,
	})
	if err != nil {
		var unk *apikeys.UnknownScopeError
		var esc *apikeys.PrivilegeEscalationError
		var dup *apikeys.DuplicateScopeError
		switch {
		case errors.Is(err, apikeys.EmptyScopesError):
			writeError(w, http.StatusBadRequest, err.Error(), "EMPTY_SCOPES")
		case errors.As(err, &dup):
			writeError(w, http.StatusBadRequest, err.Error(), "DUPLICATE_SCOPE")
		case errors.As(err, &unk):
			writeError(w, http.StatusBadRequest, err.Error(), "UNKNOWN_SCOPE")
		case errors.As(err, &esc):
			writeError(w, http.StatusForbidden, err.Error(), "PRIVILEGE_ESCALATION")
		default:
			writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL")
		}
		return
	}

	h.audit.Emit(r.Context(), audit.AuditEvent{
		ActorType:    "user",
		ActorID:      principal.UserID,
		Action:       "api_key.create",
		ResourceType: "api_key",
		ResourceID:   result.ID,
		OrgID:        principal.OrgID,
		Result:       "success",
		Details: map[string]any{
			"scopes":             result.Scopes,
			"is_service_account": result.IsServiceAccount,
			"expires_at":         result.ExpiresAt,
		},
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}
```

> Note: `h.RBACCache.AllPermissions()` is a new method — add it to `internal/policy/cache.go`:
> ```go
> func (c *Cache) AllPermissions() []string {
>     c.mu.RLock()
>     defer c.mu.RUnlock()
>     out := make([]string, 0, len(c.allPerms))
>     for p := range c.allPerms {
>         out = append(out, p)
>     }
>     return out
> }
> ```

- [ ] **Step 3: Build**

Run: `go build ./...`
Expected: exit 0.

- [ ] **Step 4: Unit test for the handler**

Create `internal/controlplane/api/apikeys_create_test.go`:

```go
package api

// Integration test: creating a key with a scope the creator doesn't
// possess returns 403 PRIVILEGE_ESCALATION.
// Creating with an unknown scope returns 400 UNKNOWN_SCOPE.
// Creating with is_service_account=true as a security_engineer returns 403.
// Creating valid scopes as admin returns 201 with plaintext.
//
// Uses the same startTestServer + IssueTokenForRole helpers from
// Phase 1 Task 10.2.

// (Full test body — see existing api tests for patterns. Table-driven
// covers: unknown scope, escalation, service-account-wrong-role, happy path.)
```

Expand with real test cases in the same pattern as the authz matrix test.

- [ ] **Step 5: Run + atomic commit (bundles Task 2.2's staged file)**

```bash
go test ./internal/controlplane/api/ -run CreateAPIKey -v
# Combine 2.2's staged apikeys.go with 2.3's handler + test + cache method.
# This is the single commit that fixes the signature change across the codebase.
git add pkg/apikeys/apikeys.go \
        internal/controlplane/api/apikeys.go \
        internal/controlplane/api/apikeys_create_test.go \
        internal/policy/cache.go
git status  # verify all four files are staged (green) and working tree is clean
git commit -m "feat(apikeys): CreateInput + enforce creator ceiling and service-account role"
# Sanity: every commit on this branch from here on must `go build ./...` cleanly.
go build ./... && echo "OK"
```

---

## Chunk 3: Rotation

### Task 3.1: Rotate function

**Files:**
- Create: `pkg/apikeys/rotate.go`
- Create: `pkg/apikeys/rotate_test.go`

- [ ] **Step 1: Write tests**

File: `pkg/apikeys/rotate_test.go`:

```go
package apikeys

import (
	"context"
	"testing"
)

func TestRotate_UpdatesHashAndPrefixAtomically(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Seed: create a key.
	in := CreateInput{
		OrgID: testOrgID(t, pool), CreatedBy: testUserID(t, pool), UserID: testUserID(t, pool),
		Name: "rotate-test", Scopes: []string{"risks.read"},
		CreatorPermissions: map[string]struct{}{"risks.read": {}},
		KnownPermissions:   map[string]struct{}{"risks.read": {}},
	}
	created, err := Create(ctx, pool, in)
	if err != nil {
		t.Fatal(err)
	}
	oldHash := Hash(created.PlainText)
	oldPrefix := created.Prefix

	// Rotate.
	rotated, err := Rotate(ctx, pool, created.ID, in.OrgID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if rotated.PlainText == created.PlainText {
		t.Fatal("plaintext should change on rotate")
	}
	if Hash(rotated.PlainText) == oldHash {
		t.Fatal("hash should change")
	}
	if rotated.Prefix == oldPrefix {
		t.Fatal("prefix should change")
	}

	// Old hash is gone — Resolve must fail.
	_, err = Resolve(ctx, pool, created.PlainText)
	if err == nil {
		t.Fatal("old plaintext should no longer resolve")
	}
	// New hash resolves.
	_, err = Resolve(ctx, pool, rotated.PlainText)
	if err != nil {
		t.Fatalf("new plaintext should resolve: %v", err)
	}
}

func TestRotate_RejectsWrongOrg(t *testing.T) {
	pool := testPool(t)
	// Create a key under org A. Attempt to rotate as org B.
	// Expect error (not-found) — tenant isolation via org_id predicate.
	// ... implementation mirrors above ...
}

func TestRotate_RejectsRevokedKey(t *testing.T) {
	pool := testPool(t)
	// Create a key, revoke it, attempt rotate → error.
}
```

(`testPool`, `testOrgID`, `testUserID` — add to a new `pkg/apikeys/testing_test.go` helper following the same pattern as `internal/policy/testing_test.go` from Phase 1.)

- [ ] **Step 2: Implement Rotate**

File: `pkg/apikeys/rotate.go`:

```go
package apikeys

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RotateResult bundles Rotate's output so the handler can audit both
// old and new prefix without a separate pre-fetch (which would introduce
// a TOCTOU window against concurrent rotates).
type RotateResult struct {
	CreateResult        // embedded: ID, PlainText, Prefix (new), Name, Scopes, ExpiresAt, IsServiceAccount
	OldPrefix    string // prefix before this rotation, captured atomically
}

// Rotate replaces the key's plaintext in a single atomic UPDATE. The old
// plaintext stops working immediately — there is no grace window where
// both tokens are valid. Returns both old and new prefix (so the handler
// can audit without a separate pre-fetch TOCTOU).
//
// Tenant isolation via org_id predicate. Fails if key is revoked or
// belongs to a different org. Uses a CTE to capture the old prefix in
// the same statement as the UPDATE — atomic, no race.
func Rotate(ctx context.Context, pool *pgxpool.Pool, keyID, orgID string) (*RotateResult, error) {
	if keyID == "" || orgID == "" {
		return nil, fmt.Errorf("keyID and orgID are required")
	}

	raw := Generate()
	hash := Hash(raw)
	prefix := PrefixOf(raw)
	now := time.Now()

	var result RotateResult
	err := pool.QueryRow(ctx, `
		WITH old AS (
		    SELECT prefix FROM core.api_keys
		    WHERE id = $4 AND org_id = $5
		)
		UPDATE core.api_keys k
		SET key_hash   = $1,
		    prefix     = $2,
		    rotated_at = $3
		FROM old
		WHERE k.id = $4
		  AND k.org_id = $5
		  AND k.revoked = false
		RETURNING k.id, k.name, k.scopes, k.expires_at, k.is_service_account, old.prefix
	`, hash, prefix, now, keyID, orgID).Scan(
		&result.ID, &result.Name, &result.Scopes, &result.ExpiresAt, &result.IsServiceAccount,
		&result.OldPrefix,
	)
	if err != nil {
		return nil, fmt.Errorf("rotate api_key: %w (key not found, revoked, or cross-tenant)", err)
	}

	result.PlainText = raw
	result.Prefix = prefix
	return &result, nil
}
```

- [ ] **Step 3: Run tests**

Run: `TEST_DATABASE_URL="$DATABASE_URL" go test ./pkg/apikeys/ -run TestRotate -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add pkg/apikeys/rotate.go pkg/apikeys/rotate_test.go pkg/apikeys/testing_test.go
git commit -m "feat(apikeys): atomic Rotate replaces hash + prefix in single UPDATE"
```

### Task 3.2: Rotate HTTP endpoint

**Files:**
- Create: `internal/controlplane/api/apikeys_rotate.go`
- Create: `internal/controlplane/api/apikeys_rotate_test.go`
- Modify: `internal/controlplane/server.go`

- [ ] **Step 1: Write the handler**

File: `internal/controlplane/api/apikeys_rotate.go`:

```go
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/sentinelcore/sentinelcore/pkg/apikeys"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

func (h *Handlers) RotateAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHENTICATED")
		return
	}

	keyID := r.PathValue("id")
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "missing key id", "BAD_REQUEST")
		return
	}

	// Single atomic call — Rotate captures old prefix via CTE in the
	// same statement as the UPDATE. No TOCTOU window.
	result, err := apikeys.Rotate(r.Context(), h.pool, keyID, principal.OrgID)
	if err != nil {
		// Discriminate: no-rows → 404 (tenant isolation or revoked).
		// Anything else → 500 (DB error, serialization failure).
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "key not found or revoked", "NOT_FOUND")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL")
		return
	}

	h.audit.Emit(r.Context(), audit.AuditEvent{
		ActorType:    "user",
		ActorID:      principal.UserID,
		Action:       "api_key.rotate",
		ResourceType: "api_key",
		ResourceID:   keyID,
		OrgID:        principal.OrgID,
		Result:       "success",
		Details: map[string]any{
			"old_prefix": result.OldPrefix,
			"new_prefix": result.Prefix,
		},
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result.CreateResult) // omit OldPrefix from response body
}
```

- [ ] **Step 2: Register route**

In `internal/controlplane/server.go`, in the `api_keys` group:

```go
mux.Handle("POST /api/v1/api-keys/{id}/rotate",
    s.authz("api_keys.manage", handlers.RotateAPIKey))
```

- [ ] **Step 3: Integration test**

File: `internal/controlplane/api/apikeys_rotate_test.go` — mirror the create test pattern: create key as admin, rotate it, confirm old plaintext returns 401 and new plaintext returns 2xx on a subsequent authenticated request.

- [ ] **Step 4: Run + commit**

```bash
TEST_DATABASE_URL="$DATABASE_URL" go test ./internal/controlplane/api/ -run RotateAPIKey -v
git add internal/controlplane/api/apikeys_rotate.go internal/controlplane/api/apikeys_rotate_test.go internal/controlplane/server.go
git commit -m "feat(apikeys): add POST /api/v1/api-keys/{id}/rotate"
```

---

## Chunk 4: Expiration Sweep + Pending-Audit Drain

### Task 4.1: Hourly expiration sweep

**Files:**
- Create: `cmd/retention-worker/sweep_api_keys.go` (or add to existing loop)

- [ ] **Step 1: Read existing retention-worker structure**

Run: `ls cmd/retention-worker/ && head -60 cmd/retention-worker/main.go`

- [ ] **Step 2: Add sweep function**

Create a new file in the same package:

```go
package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// sweepExpiredAPIKeys runs hourly. Marks any non-revoked key whose
// expires_at has passed as revoked. The middleware already rejects
// expired keys at request time (expires_at check in Resolve), so this
// is cleanup, not a security gate.
func sweepExpiredAPIKeys(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	// Run once on startup so a freshly-booted retention-worker catches
	// anything that accumulated during downtime.
	runSweep(ctx, pool, logger)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runSweep(ctx, pool, logger)
		}
	}
}

func runSweep(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	// RETURNING gives us per-key identity + org so we can write an audit
	// event for each expired key. We use pending_audit_events rather than
	// calling audit.Emit directly (the retention-worker doesn't own an
	// audit emitter; the controlplane drains pending_audit_events every
	// 30s per Task 4.2). If audit.Emit is later plumbed into retention-worker,
	// we can switch to direct emission.
	rows, err := pool.Query(ctx, `
		UPDATE core.api_keys
		SET revoked = true
		WHERE revoked = false
		  AND expires_at IS NOT NULL
		  AND expires_at < now()
		RETURNING id, org_id, prefix, user_id, expires_at
	`)
	if err != nil {
		logger.Warn("api key expiration sweep failed", "err", err)
		return
	}
	defer rows.Close()

	type expiredKey struct {
		id, orgID, prefix, userID string
		expiresAt                 time.Time
	}
	var expired []expiredKey
	for rows.Next() {
		var k expiredKey
		var userID *string
		if err := rows.Scan(&k.id, &k.orgID, &k.prefix, &userID, &k.expiresAt); err != nil {
			continue
		}
		if userID != nil {
			k.userID = *userID
		}
		expired = append(expired, k)
	}
	rows.Close()

	if len(expired) == 0 {
		return
	}

	// Emit an audit event per expired key via pending_audit_events.
	for _, k := range expired {
		_, err := pool.Exec(ctx, `
			INSERT INTO auth.pending_audit_events (org_id, event_type, resource_id, details, created_at)
			VALUES ($1, 'api_key.auto_expire', $2,
			        jsonb_build_object(
			            'reason', 'expired',
			            'prefix', $3,
			            'user_id', $4,
			            'expires_at', $5
			        ),
			        now())
		`, k.orgID, k.id, k.prefix, k.userID, k.expiresAt)
		if err != nil {
			logger.Warn("audit emit for expired key failed", "key_id", k.id, "err", err)
		}
	}

	logger.Info("api key expiration sweep", "revoked", len(expired))
}
```

- [ ] **Step 3: Wire from main**

In `cmd/retention-worker/main.go`, add to the worker's goroutine launcher:

```go
go sweepExpiredAPIKeys(ctx, pool, logger)
```

- [ ] **Step 4: Manual smoke test**

```sql
-- Setup: create a key that expired yesterday.
INSERT INTO core.api_keys (id, org_id, user_id, created_by, name, prefix, key_hash,
                           scopes, expires_at, revoked)
VALUES (gen_random_uuid(), (SELECT id FROM core.organizations LIMIT 1),
        (SELECT id FROM core.users LIMIT 1),
        (SELECT id FROM core.users LIMIT 1),
        'expired-test', 'test0001', 'dummyhash',
        ARRAY['risks.read'], now() - interval '1 day', false);
```

Restart retention-worker. Within 1 hour (or immediately on startup):

```sql
SELECT name, revoked FROM core.api_keys WHERE name = 'expired-test';
-- Expected: revoked = true
```

Clean up: `DELETE FROM core.api_keys WHERE name = 'expired-test';`

- [ ] **Step 5: Commit**

```bash
git add cmd/retention-worker/sweep_api_keys.go cmd/retention-worker/main.go
git commit -m "feat(retention): hourly sweep of expired api keys"
```

### Task 4.2: Pending-audit-events drain

**Files:**
- Create: `cmd/retention-worker/drain_pending_audit.go`

The trigger from Task 1.3 writes to `auth.pending_audit_events` when it auto-revokes keys on role downgrade. The retention-worker drains this into the NATS audit stream.

- [ ] **Step 1: Implement drain**

```go
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
)

// drainPendingAuditEvents polls the auth.pending_audit_events side
// table every 30 seconds and publishes each unprocessed row as a
// regular audit event. Marks processed=true after successful emit.
//
// This exists because Postgres triggers can't reach NATS directly.
// The trigger writes to the side table in the same transaction as
// the source mutation (role change + key revocation), guaranteeing
// at-least-once delivery.
func drainPendingAuditEvents(ctx context.Context, pool *pgxpool.Pool, emitter *audit.Emitter, logger *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		rows, err := pool.Query(ctx, `
			SELECT id, org_id, event_type, resource_id, details, created_at
			FROM auth.pending_audit_events
			WHERE processed = false
			ORDER BY created_at ASC
			LIMIT 100
		`)
		if err != nil {
			logger.Warn("drain pending audit query failed", "err", err)
			continue
		}

		var processedIDs []int64
		for rows.Next() {
			var id int64
			var orgID, eventType, resourceID string
			var details []byte
			var createdAt time.Time
			if err := rows.Scan(&id, &orgID, &eventType, &resourceID, &details, &createdAt); err != nil {
				continue
			}
			var detailsMap map[string]any
			_ = json.Unmarshal(details, &detailsMap)

			// org_id comes from the typed NOT NULL column (migration 028),
			// not JSONB — always populated by the trigger, backfill CLI,
			// and expiration sweep.
			actorID, _ := detailsMap["user_id"].(string)

			if err := emitter.Emit(ctx, audit.AuditEvent{
				Action:       eventType,
				ResourceType: "api_key",
				ResourceID:   resourceID,
				OrgID:        orgID,
				ActorType:    "system",
				ActorID:      actorID,
				Result:       "success",
				Details:      detailsMap,
				Timestamp:    createdAt,
			}); err != nil {
				logger.Warn("pending audit emit failed", "id", id, "err", err)
				continue
			}
			processedIDs = append(processedIDs, id)
		}
		rows.Close()

		if len(processedIDs) > 0 {
			_, err = pool.Exec(ctx,
				`UPDATE auth.pending_audit_events SET processed = true WHERE id = ANY($1)`,
				processedIDs)
			if err != nil {
				logger.Warn("mark processed failed", "err", err)
			}
		}
	}
}
```

- [ ] **Step 2: Wire from main**

```go
go drainPendingAuditEvents(ctx, pool, auditEmitter, logger)
```

- [ ] **Step 3: Commit**

```bash
git add cmd/retention-worker/drain_pending_audit.go cmd/retention-worker/main.go
git commit -m "feat(retention): drain pending_audit_events to NATS every 30s"
```

---

## Chunk 5: Session Revoke Listener

### Task 5.1: LISTEN user_sessions_revoke → Redis SREM

**Files:**
- Create: `internal/apikeys/session_revoke_listener.go`
- Modify: `internal/controlplane/server.go`

The trigger from Task 1.3 also fires `NOTIFY user_sessions_revoke` with the user_id as payload. Controlplane subscribes and invalidates the user's JTIs in Redis so existing JWT sessions don't outlive a role change.

- [ ] **Step 1: Write the listener**

File: `internal/apikeys/session_revoke_listener.go`:

```go
package apikeys

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// StartSessionRevokeListener listens on pg channel user_sessions_revoke.
// Payload is a user UUID. On each notification, removes all JTIs for
// that user from the Redis session store.
//
// Follows the same reconnect-with-backoff pattern as the RBAC cache
// listener in internal/policy/cache.go.
func StartSessionRevokeListener(ctx context.Context, pool *pgxpool.Pool, sessions *auth.SessionStore, logger *slog.Logger) {
	go func() {
		delay := time.Second
		for ctx.Err() == nil {
			if err := listenOnce(ctx, pool, sessions, logger); err != nil {
				logger.Warn("session revoke listener lost", "err", err, "delay", delay)
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
				if delay < 30*time.Second {
					delay *= 2
				}
				continue
			}
			delay = time.Second
		}
	}()
}

func listenOnce(ctx context.Context, pool *pgxpool.Pool, sessions *auth.SessionStore, logger *slog.Logger) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN user_sessions_revoke"); err != nil {
		return err
	}
	logger.Info("session revoke listener started")

	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		userID := n.Payload
		if userID == "" {
			continue
		}
		if err := sessions.RevokeAllForUser(ctx, userID); err != nil {
			logger.Warn("revoke user sessions failed", "user_id", userID, "err", err)
			continue
		}
		logger.Info("user sessions revoked on role change", "user_id", userID)
	}
}
```

> Note: `SessionStore.RevokeAllForUser(ctx, userID)` is a new method — add to `pkg/auth/session.go`. Implementation: iterate all JTIs for the user (sessions are indexed by JTI; we need a secondary index `user:{user_id}:sessions` → set of JTIs populated on session create) and remove each.

- [ ] **Step 2: Add SessionStore.RevokeAllForUser + user-indexed JTI tracking**

In `pkg/auth/session.go`:
- On `CreateSession(jti, userID)`: also `SADD user:{userID}:sessions jti` (and `EXPIRE` the set to access-token TTL + refresh-token TTL so abandoned sets GC themselves).
- On `RevokeSession(jti)`: also pull the user_id from the session record and `SREM user:{userID}:sessions jti`.
- Add:
  ```go
  func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
      // Pipeline-based drain: use SPOP in a loop rather than SMembers+Del.
      // SPOP removes one JTI atomically per call, so a concurrent
      // CreateSession racing our drain either (a) adds a new JTI that we
      // haven't popped yet (drained on the next iteration) or (b) adds
      // after we finish — that session is legitimately post-revoke and
      // should keep working.
      key := "user:" + userID + ":sessions"
      for {
          jti, err := s.client.SPop(ctx, key).Result()
          if err == redis.Nil {
              return nil // set empty / gone
          }
          if err != nil {
              return err
          }
          // RevokeSession deletes the session:<jti> hash. We're already
          // SPOP-ed from the index set, so no SREM needed here.
          _ = s.client.Del(ctx, "session:"+jti).Err()
      }
  }
  ```
  Note: `RevokeSession` in CreateSession's companion path still does `SREM` for single-JTI revokes (from /auth/logout). The pipeline above is only used when draining an entire user.

- [ ] **Step 3: Unit test**

Test that after `RevokeAllForUser`, `IsActive(jti)` returns false for every JTI the user had. Add a concurrency test: start 10 goroutines creating sessions for user U while `RevokeAllForUser(U)` runs; assert no JTI leaks (every surviving JTI was created *after* the drain call started, or is absent).

- [ ] **Step 4: Wire from server**

In `internal/controlplane/server.go`'s constructor or Start method:

```go
apikeys.StartSessionRevokeListener(ctx, s.pool, s.sessions, s.logger)
```

- [ ] **Step 5: One-shot JTI backfill on deploy**

The user-indexed set `user:{userID}:sessions` is only populated by `CreateSession` from this deploy forward. Sessions created *before* the deploy exist as `session:{jti}` keys in Redis but have no entry in any user set — so a role-downgrade in the first hour post-deploy would `SPOP` an empty set, leaving those JWTs live until their 15m access-TTL expires (plus up to 7d refresh-TTL for refresh-flow paths).

Run this one-shot backfill IMMEDIATELY after Task 5.1 ships, BEFORE enabling the trigger-based revocation in production:

Create `cmd/backfill-jti-index/main.go`:

```go
// Scans all session:* keys in Redis and populates the user-indexed
// sets (user:{userID}:sessions) so SessionStore.RevokeAllForUser works
// for sessions issued before Phase 2.
package main

import (
    "context"
    "flag"
    "log/slog"
    "os"
    "strings"
    "time"

    "github.com/redis/go-redis/v9"
)

func main() {
    redisURL := flag.String("redis", os.Getenv("REDIS_URL"), "redis URL")
    flag.Parse()

    opt, err := redis.ParseURL(*redisURL)
    if err != nil { slog.Error("parse", "err", err); os.Exit(1) }
    c := redis.NewClient(opt)
    ctx := context.Background()

    var (
        cursor  uint64
        scanned int
        indexed int
    )
    for {
        keys, nextCursor, err := c.Scan(ctx, cursor, "session:*", 500).Result()
        if err != nil { slog.Error("scan", "err", err); os.Exit(1) }
        for _, key := range keys {
            jti := strings.TrimPrefix(key, "session:")
            userID, err := c.HGet(ctx, key, "user_id").Result()
            if err != nil || userID == "" { continue }
            _ = c.SAdd(ctx, "user:"+userID+":sessions", jti).Err()
            // Match the set TTL to the max possible session life so
            // stale entries GC themselves (matches CreateSession's EXPIRE).
            _ = c.Expire(ctx, "user:"+userID+":sessions", 7*24*time.Hour).Err()
            indexed++
        }
        scanned += len(keys)
        if nextCursor == 0 { break }
        cursor = nextCursor
    }
    slog.Info("backfill complete", "scanned", scanned, "indexed", indexed)
}
```

Run on production before enabling the trigger:

```bash
go run ./cmd/backfill-jti-index -redis $REDIS_URL
# Expected: scanned=<N>, indexed=<N-stale>; verify with redis-cli SCARD user:<some-user>:sessions
```

**Sequencing matters:** if the trigger fires before this backfill runs, role-downgrade revocations silently miss pre-deploy sessions. Run order on deploy day:
1. Deploy binary with `StartSessionRevokeListener` (still safe: no triggers exist yet).
2. Apply migration 028 (trigger now exists and emits NOTIFY).
3. Immediately run `backfill-jti-index` (takes seconds to minutes).
4. Announce role-change capability to admins.

If step 3 is skipped or fails, document it in the runbook and optionally force-logout all users (set `revoked=true` on all `session:*` hashes) rather than ship with an invisible gap.

- [ ] **Step 6: Run + commit**

```bash
go test ./pkg/auth/ -run RevokeAllForUser -v
git add internal/apikeys/session_revoke_listener.go \
        pkg/auth/session.go \
        internal/controlplane/server.go \
        cmd/backfill-jti-index/main.go
git commit -m "feat(auth): LISTEN user_sessions_revoke → SPOP user JTIs from Redis + JTI index backfill"
```

---

## Chunk 6: Backfill

### Task 6.1: Build the backfill CLI

**Files:**
- Create: `cmd/migrate-api-keys/main.go`
- Create: `cmd/migrate-api-keys/README.md`

The CLI has three modes:

- `preview` — writes `proposed_scopes` to every eligible row, prints the count.
- `execute --org-id <uuid>` — applies the backfill for one tenant.
- `execute --all` — applies for all tenants in creation order.

Eligible rows = keys with `scopes = '{}' OR array_length(scopes, 1) IS NULL`.

Proposed scopes = `{risks.read, findings.read, scans.read, scans.run, targets.read, audit.read}` filtered to creator's current permissions.

- [ ] **Step 1: Skeleton**

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var defaultSafeScopes = []string{
	"risks.read", "findings.read", "scans.read",
	"scans.run", "targets.read", "audit.read",
}

func main() {
	mode := flag.String("mode", "", "preview | execute")
	orgID := flag.String("org-id", "", "org UUID (execute mode)")
	all := flag.Bool("all", false, "execute for all orgs (execute mode)")
	flag.Parse()

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	must(err)
	defer pool.Close()

	switch *mode {
	case "preview":
		must(runPreview(ctx, pool))
	case "execute":
		if *all {
			must(runExecuteAll(ctx, pool))
		} else if *orgID != "" {
			must(runExecuteOrg(ctx, pool, *orgID))
		} else {
			fmt.Fprintln(os.Stderr, "execute mode requires --org-id <uuid> or --all")
			os.Exit(2)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: migrate-api-keys -mode preview|execute [-org-id UUID | -all]")
		os.Exit(2)
	}
}
```

- [ ] **Step 2: Preview mode**

```go
func runPreview(ctx context.Context, pool *pgxpool.Pool) error {
	// For each eligible key, compute proposed = defaultSafeScopes ∩ creator's permissions.
	rows, err := pool.Query(ctx, `
		SELECT k.id, k.org_id, k.created_by, u.role
		FROM core.api_keys k
		JOIN core.users u ON u.id = k.created_by
		WHERE k.revoked = false
		  AND (k.scopes = '{}' OR array_length(k.scopes, 1) IS NULL)
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Cache role→perms across the entire run. There are only 5 roles, so
	// this replaces N queries (one per key) with ≤5. Critical for tenants
	// with thousands of keys.
	roleCache := make(map[string]map[string]struct{})
	getPerms := func(role string) (map[string]struct{}, error) {
		if p, ok := roleCache[role]; ok {
			return p, nil
		}
		p, err := loadRolePerms(ctx, pool, role)
		if err != nil {
			return nil, err
		}
		roleCache[role] = p
		return p, nil
	}

	var updated int
	for rows.Next() {
		var keyID, orgID, createdBy, role string
		if err := rows.Scan(&keyID, &orgID, &createdBy, &role); err != nil {
			return err
		}

		creatorPerms, err := getPerms(role)
		if err != nil {
			return err
		}
		var proposed []string
		for _, s := range defaultSafeScopes {
			if _, ok := creatorPerms[s]; ok {
				proposed = append(proposed, s)
			}
		}

		_, err = pool.Exec(ctx,
			`UPDATE core.api_keys SET proposed_scopes = $1 WHERE id = $2`,
			proposed, keyID)
		if err != nil {
			return err
		}
		updated++
	}
	fmt.Printf("Preview: %d keys will have proposed_scopes set.\n", updated)
	return nil
}
```

- [ ] **Step 3: Execute mode (single org + all)**

```go
func runExecuteOrg(ctx context.Context, pool *pgxpool.Pool, orgID string) error {
	return executeForOrg(ctx, pool, orgID)
}

func runExecuteAll(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `SELECT id FROM core.organizations ORDER BY created_at ASC`)
	if err != nil {
		return err
	}
	var orgIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		orgIDs = append(orgIDs, id)
	}
	rows.Close()

	for i, org := range orgIDs {
		fmt.Printf("[%d/%d] Backfilling org %s...\n", i+1, len(orgIDs), org)
		if err := executeForOrg(ctx, pool, org); err != nil {
			return fmt.Errorf("org %s: %w", org, err)
		}
		// Small pause between orgs — lets monitoring dashboards catch up.
		time.Sleep(2 * time.Second)
	}
	return nil
}

func executeForOrg(ctx context.Context, pool *pgxpool.Pool, orgID string) error {
	// Single transaction per org.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Require preview to have run for every eligible key: refuse to execute
	// if any key has empty scopes but no proposed_scopes set. Previously the
	// UPDATE fell back to defaultSafeScopes via COALESCE, but that path
	// bypassed the audit-event INSERT below (which filters on
	// proposed_scopes IS NOT NULL). Refusing here keeps the invariant
	// "every scope change is audited."
	var missingPreview int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM core.api_keys
		WHERE org_id = $1
		  AND (scopes = '{}' OR array_length(scopes, 1) IS NULL)
		  AND proposed_scopes IS NULL
		  AND revoked = false
	`, orgID).Scan(&missingPreview)
	if err != nil {
		return err
	}
	if missingPreview > 0 {
		return fmt.Errorf("org %s: %d keys have empty scopes but no proposed_scopes — run preview first", orgID, missingPreview)
	}

	// Execute uses proposed_scopes exclusively — defaultSafeScopes is
	// only consulted during preview (runPreviewAll). Requiring the
	// per-key proposed_scopes at execute time keeps the invariant
	// "every scope change is audited" (the INSERT below filters on
	// proposed_scopes IS NOT NULL).
	tag, err := tx.Exec(ctx, `
		UPDATE core.api_keys
		SET scopes = proposed_scopes
		WHERE org_id = $1
		  AND (scopes = '{}' OR array_length(scopes, 1) IS NULL)
		  AND proposed_scopes IS NOT NULL
		  AND revoked = false
	`, orgID)
	if err != nil {
		return err
	}

	// Emit a backfill event per key. The trigger in Task 1.3 doesn't
	// fire on UPDATE OF scopes (it's only on role change), so we
	// record the backfill ourselves via the pending_audit_events table.
	// org_id is written to the typed column (introduced in migration
	// 028 with the trigger) so the drainer tenant-scopes NATS emits
	// without JSONB parsing.
	_, err = tx.Exec(ctx, `
		INSERT INTO auth.pending_audit_events (org_id, event_type, resource_id, details, created_at)
		SELECT org_id, 'api_key.backfill', id::text,
			   jsonb_build_object('org_id', org_id, 'scopes', scopes, 'reason', 'phase_2_backfill'),
			   now()
		FROM core.api_keys
		WHERE org_id = $1
		  AND proposed_scopes IS NOT NULL
	`, orgID)
	if err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("  backfilled %d keys for org %s\n", tag.RowsAffected(), orgID)
	return nil
}

func loadRolePerms(ctx context.Context, pool *pgxpool.Pool, role string) (map[string]struct{}, error) {
	rows, err := pool.Query(ctx,
		`SELECT permission_id FROM auth.role_permissions WHERE role_id = $1`, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out[p] = struct{}{}
	}
	return out, nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 4: README**

Document the backfill timeline:

```markdown
# migrate-api-keys

One-shot CLI for Phase 2 API-key scope backfill. Run after Phase 1
is deployed and tenants have been notified.

## Timeline

T-10 days: email + dashboard banner to all Owners announcing the scope migration. (Spec requires ≥10 working days notice.)
T-7 days: run `migrate-api-keys preview --all` in production. Dashboard banner shows per-key proposed scopes to Owner/Admin.
T-1 day: final reminder banner.
T-0: run `migrate-api-keys execute --all` in a maintenance window.
T+30 days: drop the `proposed_scopes` column via migration 029 (future). (30 days matches the spec's retention window for rollback — not the 7-day value previously listed here.)

## Emergency bypass

If a tenant's CI pipeline breaks due to tightened scopes, an Owner/Admin
can re-scope their key via the UI (Settings → API Keys) in one click.
Keys with custom scopes (scopes <> '{}') are untouched by the backfill.
```

- [ ] **Step 5: Integration test on staging**

Manual in staging:
```bash
DATABASE_URL=$STAGING_DATABASE_URL go run ./cmd/migrate-api-keys -mode preview
# Inspect: proposed_scopes column populated.
DATABASE_URL=$STAGING_DATABASE_URL go run ./cmd/migrate-api-keys -mode execute -all
# Verify scopes applied, pending_audit_events drained by retention-worker.
```

- [ ] **Step 6: Commit**

```bash
git add cmd/migrate-api-keys/
git commit -m "feat(apikeys): one-shot backfill CLI (preview + per-tenant execute)"
```

---

## Chunk 7: Frontend

### Task 7.1: API client + hooks

**Files:**
- Create: `web/features/api-keys/api.ts`
- Create: `web/features/api-keys/hooks.ts`

- [ ] **Step 1: api.ts**

```ts
import { api } from "@/lib/api-client";

export interface APIKey {
  id: string;
  name: string;
  description?: string;
  prefix: string;
  scopes: string[];
  is_service_account: boolean;
  created_by: string;
  created_at: string;
  last_used_at?: string;
  rotated_at?: string;
  expires_at?: string;
  revoked: boolean;
}

export interface CreateKeyRequest {
  name: string;
  description?: string;
  scopes: string[];
  expires_in?: string;
  is_service_account?: boolean;
}

export interface CreateKeyResponse extends APIKey {
  plaintext: string; // shown once
}

export async function listKeys(): Promise<APIKey[]> {
  const res = await api.get<{ api_keys: APIKey[] }>("/api/v1/api-keys");
  return res.api_keys;
}

export async function createKey(req: CreateKeyRequest): Promise<CreateKeyResponse> {
  return api.post<CreateKeyResponse>("/api/v1/api-keys", req);
}

export async function rotateKey(id: string): Promise<CreateKeyResponse> {
  return api.post<CreateKeyResponse>(`/api/v1/api-keys/${id}/rotate`);
}

export async function revokeKey(id: string): Promise<void> {
  await api.delete(`/api/v1/api-keys/${id}`);
}
```

- [ ] **Step 2: hooks.ts**

```ts
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listKeys, createKey, rotateKey, revokeKey } from "./api";

export function useKeys() {
  return useQuery({ queryKey: ["api-keys"], queryFn: listKeys });
}

export function useCreateKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createKey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });
}

export function useRotateKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: rotateKey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });
}

export function useRevokeKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: revokeKey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });
}
```

- [ ] **Step 3: Commit**

```bash
git add web/features/api-keys/api.ts web/features/api-keys/hooks.ts
git commit -m "feat(web/api-keys): data layer — api.ts + hooks.ts"
```

### Task 7.2: Scope picker

**Files:**
- Create: `web/features/api-keys/scope-picker.tsx`
- Create: `web/features/api-keys/scope-picker.test.tsx`

- [ ] **Step 1: Test**

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { ScopePicker } from "./scope-picker";

describe("ScopePicker", () => {
  it("groups scopes by category", () => {
    render(
      <ScopePicker
        available={["risks.read", "risks.resolve", "scans.run"]}
        ceiling={new Set(["risks.read", "risks.resolve", "scans.run"])}
        selected={[]}
        onChange={() => {}}
      />
    );
    expect(screen.getByText("risks")).toBeInTheDocument();
    expect(screen.getByText("scans")).toBeInTheDocument();
  });

  it("grays out scopes exceeding the ceiling", () => {
    render(
      <ScopePicker
        available={["risks.read", "users.manage"]}
        ceiling={new Set(["risks.read"])}
        selected={[]}
        onChange={() => {}}
      />
    );
    const usersBox = screen.getByLabelText(/users\.manage/);
    expect(usersBox).toBeDisabled();
  });

  it("toggles selection", () => {
    const onChange = vi.fn();
    render(
      <ScopePicker
        available={["risks.read"]}
        ceiling={new Set(["risks.read"])}
        selected={[]}
        onChange={onChange}
      />
    );
    fireEvent.click(screen.getByLabelText(/risks\.read/));
    expect(onChange).toHaveBeenCalledWith(["risks.read"]);
  });
});
```

- [ ] **Step 2: Implement**

```tsx
"use client";

import { useMemo } from "react";

export interface ScopePickerProps {
  available: string[];       // full permission catalog
  ceiling: Set<string>;      // current user's own permissions
  selected: string[];
  onChange: (next: string[]) => void;
}

export function ScopePicker({ available, ceiling, selected, onChange }: ScopePickerProps) {
  const grouped = useMemo(() => {
    const groups: Record<string, string[]> = {};
    for (const perm of available) {
      const category = perm.split(".")[0] ?? "misc";
      (groups[category] ??= []).push(perm);
    }
    return groups;
  }, [available]);

  const selectedSet = new Set(selected);

  const toggle = (perm: string) => {
    if (selectedSet.has(perm)) {
      onChange(selected.filter((s) => s !== perm));
    } else {
      onChange([...selected, perm]);
    }
  };

  return (
    <div className="space-y-4">
      {Object.entries(grouped).map(([cat, perms]) => (
        <fieldset key={cat} className="rounded-md border p-3">
          <legend className="px-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {cat}
          </legend>
          <div className="mt-2 grid grid-cols-1 gap-1 sm:grid-cols-2">
            {perms.map((p) => {
              const exceeds = !ceiling.has(p);
              return (
                <label
                  key={p}
                  className={`flex items-center gap-2 text-sm ${exceeds ? "text-muted-foreground/50" : ""}`}
                  title={exceeds ? "Your role does not have this permission, so you cannot grant it" : undefined}
                >
                  <input
                    type="checkbox"
                    aria-label={p}
                    disabled={exceeds}
                    checked={selectedSet.has(p)}
                    onChange={() => toggle(p)}
                  />
                  <code className="font-mono text-xs">{p}</code>
                </label>
              );
            })}
          </div>
        </fieldset>
      ))}
    </div>
  );
}
```

- [ ] **Step 3: Run test + commit**

```bash
npm test -- scope-picker
git add web/features/api-keys/scope-picker.tsx web/features/api-keys/scope-picker.test.tsx
git commit -m "feat(web/api-keys): scope picker with ceiling grayout"
```

### Task 7.3: Create-key dialog + plaintext modal

**Files:**
- Create: `web/features/api-keys/create-key-dialog.tsx`
- Create: `web/features/api-keys/key-plaintext-modal.tsx`

(Implementation follows the existing form-dialog patterns in `web/features/auth-profiles/auth-profile-form-dialog.tsx`. Key details:

- Form fields: name (required), description, scopes (ScopePicker), expires_in dropdown ("30d"/"60d"/"90d"/"1y"/"never"), is_service_account checkbox (only shown to Owner/Admin).
- On successful create: close dialog, open the plaintext modal with `result.plaintext`, a copy-to-clipboard button, and the exact warning: "This is the only time you will see this key. Save it securely now."
- The plaintext modal has only one dismiss action ("I've saved it"). No X in the corner.)

- [ ] **Step 1: Implement dialogs** (details in the existing dialog patterns)

- [ ] **Step 2: Commit**

```bash
git add web/features/api-keys/create-key-dialog.tsx web/features/api-keys/key-plaintext-modal.tsx
git commit -m "feat(web/api-keys): create dialog + one-time plaintext modal"
```

### Task 7.4: API keys table + page

**Files:**
- Create: `web/features/api-keys/api-keys-table.tsx`
- Create: `web/app/(dashboard)/api-keys/page.tsx`

Table columns per spec:
- Prefix (monospace, e.g. `sc_a1b2c3d4…`)
- Name + description (2-line)
- Principal (user email OR "Service account")
- Scopes (first 3 chips + "+N more")
- Created (relative time)
- Last used (relative time)
- Expires (relative + red if expired)
- Actions (Rotate · Revoke, both behind confirmation dialogs)

- [ ] **Step 1: Implement table + page**

Follow `web/features/auth-profiles/auth-profiles-table.tsx` as the pattern. Use `<Can permission="api_keys.manage">` to gate the Create button.

- [ ] **Step 2: Wire sidebar + palette**

In `web/components/layout/sidebar.tsx`, add the nav item (gated by `api_keys.read`):

```tsx
<Can permission="api_keys.read">
  <NavLink href="/api-keys" ...>API Keys</NavLink>
</Can>
```

In `web/components/layout/command-palette.tsx`, add to the Pages group:

```tsx
{ label: "API Keys", href: "/api-keys" },
```

- [ ] **Step 3: Commit**

```bash
git add web/features/api-keys/api-keys-table.tsx web/app/\(dashboard\)/api-keys/page.tsx web/components/layout/sidebar.tsx web/components/layout/command-palette.tsx
git commit -m "feat(web/api-keys): table + page + sidebar + palette nav"
```

---

## Verification Checklist

### Build / test gates

- [ ] Migrations 026, 027, 028 apply cleanly
- [ ] `go test ./pkg/apikeys/ -race` passes including scope validation, rotate, and create tests
- [ ] `go test ./internal/controlplane/api/ -race -run "(CreateAPIKey|RotateAPIKey)"` passes
- [ ] Frontend `npm test` passes (scope-picker tests)

### Scope enforcement

- [ ] As `security_engineer`, attempt to create a key with `users.manage` scope → 403 `PRIVILEGE_ESCALATION` with `users.manage` in error body
- [ ] As `admin`, create a key with `users.read` (admin has it) → 201, plaintext returned
- [ ] As `admin`, attempt to create a key with `users.manage` (admin does NOT have it — only Owner does) → 403 `PRIVILEGE_ESCALATION`
- [ ] Use a key whose scopes include `scans.run` to hit `POST /api/v1/scans` → 2xx
- [ ] Use a key whose scopes do NOT include `scans.run` → 403 `INSUFFICIENT_SCOPE` + `authz.denied` audit event fires

### Service accounts

- [ ] As `security_engineer`, attempt `is_service_account=true` → 403
- [ ] As `admin`, create a service-account key → 201, row has `user_id IS NULL`, `is_service_account=true`
- [ ] Use the service-account key → `Principal.UserID` is empty in middleware, scopes enforce normally
- [ ] Hit `GET /api/v1/auth/me` with the service-account key → response has `user: null`, `role: ""`, `permissions: [<scopes>]` (validates the `userID == ""` code path through `auth.me`)
- [ ] Attempt to create a service-account key using another API key → 403 FORBIDDEN with code indicating "API keys cannot create service accounts" (validates Chunk 2 `Kind == "api_key"` guard)

### Rotation

- [ ] Create key, rotate, confirm old plaintext returns 401 `INVALID_KEY`
- [ ] Confirm new plaintext works immediately (no grace window)
- [ ] `rotated_at` column updated in DB
- [ ] Audit event `api_key.rotate` emitted with `old_prefix` + `new_prefix`

### Expiration

- [ ] Create key with `expires_in=1s`, wait 2s, use it → 401 `KEY_EXPIRED`
- [ ] retention-worker logs confirm hourly sweep running
- [ ] After sweep, `revoked = true` for expired keys

### Role-downgrade trigger

- [ ] Setup: admin user with a key that has `users.manage` scope (admin does NOT, but build the test row directly via SQL for the test); downgrade user to developer
- [ ] Immediately after UPDATE: key `revoked = true`, pending_audit_event row created
- [ ] `NOTIFY user_sessions_revoke` payload = user_id
- [ ] Within 30s: event appears in NATS audit stream with `reason=role_downgrade`
- [ ] Within 10ms of notify: all Redis JTIs for that user are invalidated (requires manual Redis inspection or test helper)

### Backfill

- [ ] In staging, run `migrate-api-keys -mode preview` → `proposed_scopes` populated
- [ ] Run `migrate-api-keys -mode execute -all` → scopes set on pre-existing keys
- [ ] Audit events drain via retention-worker within 30s
- [ ] Keys previously unable to authenticate (blanket access) now succeed on the 6 default safe scopes; hit any other route → 403 INSUFFICIENT_SCOPE

### Frontend

- [ ] As `auditor` (has `api_keys.read` only), API Keys page loads in read-only mode — Create button hidden, Rotate/Revoke buttons hidden
- [ ] As `admin`, Create dialog opens, ScopePicker shows all 41 permissions grouped by category
- [ ] Scopes exceeding admin's ceiling (only `users.manage`) are grayed out with title tooltip
- [ ] Successful creation opens plaintext modal; modal has no X close button; copy-to-clipboard button works; dismissing the modal is the only way to proceed
- [ ] Revoke action prompts for confirmation; after confirmation, key row shows "Revoked" badge and actions are hidden

### Security

- [ ] Plaintext never appears in server logs (grep the logs after creating a key)
- [ ] Plaintext not in the database (`SELECT key_hash FROM core.api_keys LIMIT 1` — hash-only)
- [ ] Cross-tenant rotate attempt returns 404, not 403 (no existence oracle)

## Notes on Execution

- **Backfill is the highest-impact step.** Run Task 6.1 preview in staging first; collect the "top 10 keys by scope breadth" for communication to affected tenants.
- **Trigger testing must happen in staging before production deploy** — the trigger fires on every role UPDATE, including future user management operations. Verify it doesn't break legitimate role changes.
- **Service-account keys persist across creator changes** — that's by design but documented clearly in the audit log (`created_by` stays pointed at the original creator's user_id).
- **Phase 2 is deployable in one binary rollout.** Migrations 026, 027, 028 are cumulative and non-breaking. The backfill CLI is a separate ops step run after the deploy stabilizes.
