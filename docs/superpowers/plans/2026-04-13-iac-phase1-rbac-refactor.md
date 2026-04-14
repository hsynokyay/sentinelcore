# IAC Phase 1 — RBAC Refactor Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded 4-role permission matrix with a DB-backed 5-role capability permission system, enforced at middleware level via `RequirePermission` decorators.

**Architecture:** Three new tables (`auth.roles`, `auth.permissions`, `auth.role_permissions`) store the matrix. A process-level cache loaded at startup and refreshed via `pg_notify` serves all permission checks — zero DB hits on the hot path. A `Principal` abstraction replaces the existing `UserContext`. A `RequirePermission(perm)` middleware decorator replaces ~50 inline `policy.Evaluate(role, perm)` calls scattered across handlers. JWT stays unchanged; a `compatMode` translator in `ValidateToken()` handles old role strings in in-flight JWTs for 14 days.

**Tech Stack:** Go 1.26, PostgreSQL 16 (pgx/v5), Redis (session store), existing `pkg/audit` NATS emitter, Next.js 16 frontend.

**Related spec:** `docs/superpowers/specs/2026-04-13-identity-access-control-design.md` (Phase 1 sections).

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `migrations/024_rbac_tables.up.sql` + `.down.sql` | Create `auth.roles`, `auth.permissions`, `auth.role_permissions`; seed 5 roles + ~25 permissions + role_permissions matrix |
| `migrations/025_users_role_rename.up.sql` + `.down.sql` | Rewrite existing `core.users.role` values; update CHECK constraint |
| `internal/policy/cache.go` | Process-level RBAC cache with `Reload()` + `pg_notify` listener |
| `internal/policy/cache_test.go` | Cache unit tests (reload, concurrent read, notify handling) |
| `pkg/auth/principal.go` | `Principal` struct + `PrincipalFromContext` / `WithPrincipal` helpers |
| `pkg/auth/principal_test.go` | Principal context round-trip tests |
| `pkg/auth/require_permission.go` | `RequirePermission(perm, next)` middleware decorator + audit on deny |
| `pkg/auth/require_permission_test.go` | Middleware unit tests (allow, deny, audit emission) |
| `internal/controlplane/api/me.go` | `GET /api/v1/auth/me` handler |
| `internal/controlplane/api/me_test.go` | `/auth/me` integration tests |
| `web/features/auth/use-permissions.ts` | React hook that reads `/auth/me` and exposes `can(permission)` |
| `web/components/security/can.tsx` | `<Can permission="...">` component for UI gating |

### Modified files

| File | Change |
|---|---|
| `pkg/auth/jwt.go` | Add `compatMode` role translator at the end of `ValidateToken()` |
| `pkg/auth/middleware.go` | Replace `UserContext` with `Principal`; add `principal` key; wire cache lookup for user JWTs; scope fall-through for API keys |
| `internal/policy/rbac.go` | Gut the in-memory matrix; keep `Evaluate()` as a temporary compat shim delegating to cache (removed in last task) |
| `internal/controlplane/server.go` | Wire up cache init at startup; wrap all authenticated routes with `RequirePermission(perm)`; register `/auth/me` |
| `cmd/controlplane/main.go` | Call `policy.InitCache(ctx, pool)` before server starts |
| All `internal/controlplane/api/*.go` handlers (~20 files) | Remove inline `policy.Evaluate` calls (now handled by middleware) |
| `web/features/auth/hooks.ts` | Extend `useAuth()` to call `/auth/me` after login |
| `web/components/layout/sidebar.tsx` | Gate nav items with `<Can>` |

---

## Task Overview (bite-sized, TDD)

1. Migrations (schema + seed + compat)
2. RBAC cache
3. Principal abstraction
4. compatMode JWT translator
5. RequirePermission middleware
6. /auth/me endpoint
7. Route migration (incremental, ~20 handlers)
8. pg_notify reload wiring
9. Frontend useAuth + `<Can>`
10. Remove legacy `policy.Evaluate`
11. Integration test: every route × every role

---

## Deploy Sequencing & Rollback Procedure

Because this phase changes both the **DB schema** (role rename) and the **binary's authorization code** (RequirePermission + compat translator), the order of operations at deploy time matters. Getting it wrong produces a "locked out" window where requests 403 because the binary expects one role vocabulary and the DB stores the other.

### The safe deploy order

```
T0: Pre-deploy state
    DB schema: pre-Phase-1 (old role strings, no auth.* tables)
    Binary:    pre-Phase-1 (inline policy.Evaluate on old roles)

T1: Deploy new binary FIRST (migration 024 NOT yet applied)
    - Binary must be able to run against pre-migration DB.
    - It uses `policy.Evaluate` as a compat shim delegating to the cache.
    - The cache Reload() must tolerate auth.* tables not existing:
      if `ERROR: relation "auth.role_permissions" does not exist`,
      the cache stays empty and the compat shim falls back to the
      legacy hardcoded matrix.
    - The compat JWT translator is active but has nothing to translate
      yet (role strings are still old).
    - Verify: live traffic passes; /api/v1/auth/me returns old role names.

T2: Apply migration 024 (RBAC tables + seed)
    - Cache reloads via 60s safety poll (or manual NOTIFY).
    - policy.Evaluate now delegates to cache with old role names.
      Cache has `owner/admin/...` rows only, so old roles won't match.
    - CRITICAL: the compat shim in internal/policy/rbac.go must translate
      old→new BEFORE calling cache.Can(). (See Task 10.1's shim code.)
    - Verify: /api/v1/auth/me now returns live permission set for
      users whose JWT role still says "platform_admin" but gets
      translated to "owner".

T3: Apply migration 025 (role rename)
    - core.users.role values rewritten to new vocabulary.
    - Redis session records are role-agnostic (they only hold JTI +
      user_id + activity timestamp), so NO Redis mutation needed.
    - In-flight JWTs still carry old role strings; compat translator
      handles them at validation time.
    - Verify: `SELECT DISTINCT role FROM core.users;` returns only
      the 5 new values.

T4: Wait for JWT rollover (max 15 minutes for access tokens,
    7 days for refresh tokens — but refresh re-issues with the
    current DB role, so new access tokens get new role strings
    even during the refresh window).

T5: +14 days — remove compat translator (Task 10.3).
```

### Rollback decision tree

```
Problem?
├── Binary deploy broke traffic?
│   └── Migration 024 NOT yet applied → roll binary back. No DB state
│       to undo. Pre-migration binary + pre-migration DB = original state.
│
├── Migration 024 applied, traffic broken?
│   └── Run migrations/024_rbac_tables.down.sql (drops the tables).
│       The new binary, running without auth.* tables, falls back to
│       its hardcoded matrix (compat shim). Verify traffic recovers.
│       Then decide whether to roll binary back or fix forward.
│
├── Migration 025 applied, traffic broken?
│   ├── No developer users created yet?
│   │   └── Run migrations/025_users_role_rename.down.sql.
│   │       Guard will pass; role strings revert; compat translator
│   │       becomes a no-op. System returns to T2 state.
│   │
│   └── Developer users already created OR admins modified post-migration?
│       └── DO NOT roll back — data loss. Fix forward: roll binary
│           forward to a patched version while DB stays at migration 025.
│           Escalate to incident commander; review what the fix should be.
│
└── Post-T5 (compat translator removed) — issue surfaces?
    └── Roll binary forward to restore the translator, then diagnose.
        Do NOT roll DB back.
```

### Pre-deploy dry-run checklist

Run all of these in staging with production-sized data before T1:

- [ ] Apply 024 + 025 migrations on a copy of prod DB. Verify counts match seed expectations.
- [ ] Deploy new binary against migrated staging. Confirm every role token can hit /api/v1/auth/me and receive a non-empty permission list.
- [ ] Deploy OLD binary against migrated staging. Confirm it still serves 200s on routes that existed pre-migration (the compat shim in legacy code path must tolerate the new role strings via the compat translator at JWT validate time).
- [ ] Roll 025 back (no developer users exist yet) and confirm traffic still works on both old and new binaries.
- [ ] Roll 024 back and confirm the same.

Only after all five items pass in staging is the production deploy allowed to proceed.

---

## Chunk 1: Database Schema & Migrations

### Task 1.1: Create RBAC tables migration

**Files:**
- Create: `migrations/024_rbac_tables.up.sql`
- Create: `migrations/024_rbac_tables.down.sql`

- [ ] **Step 1: Write the up migration**

File: `migrations/024_rbac_tables.up.sql`:

```sql
BEGIN;

CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    is_builtin  BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.permissions (
    id          TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    category    TEXT NOT NULL
);

CREATE TABLE auth.role_permissions (
    role_id       TEXT NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES auth.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ── Seed: roles ─────────────────────────────────────────────────
INSERT INTO auth.roles (id, name, description) VALUES
    ('owner',             'Owner',             'Full control. Only role that can manage users, SSO, or delete the org.'),
    ('admin',             'Admin',             'Full operational control. Settings, scans, targets, API keys, SSO. Cannot manage users.'),
    ('security_engineer', 'Security Engineer', 'Day-to-day security work: scans, triage, risk resolution, audit read.'),
    ('auditor',           'Auditor',           'Read-only across the board + audit log.'),
    ('developer',         'Developer',         'Least privilege: reads risks/findings, acknowledges risks.');

-- ── Seed: permissions ───────────────────────────────────────────
-- 41 permissions total — covers every protected route in the codebase.
-- Before adding or removing a permission, update the route→permission
-- mapping in the plan (Task 7.3).
INSERT INTO auth.permissions (id, description, category) VALUES
    -- risks
    ('risks.read',                 'Read risk clusters',                          'risks'),
    ('risks.resolve',              'Resolve risk clusters',                       'risks'),
    ('risks.mute',                 'Mute risk clusters',                          'risks'),
    ('risks.reopen',               'Reopen risk clusters',                        'risks'),
    ('risks.acknowledge',          'Acknowledge a risk',                          'risks'),
    ('risks.rebuild',              'Rebuild risk correlation for a project',      'risks'),
    -- findings
    ('findings.read',              'Read findings',                               'findings'),
    ('findings.triage',            'Triage findings (assign, set status)',        'findings'),
    ('findings.legal_hold',        'Place legal hold on findings',                'findings'),
    -- scans
    ('scans.read',                 'Read scan jobs',                              'scans'),
    ('scans.run',                  'Run scans',                                   'scans'),
    ('scans.cancel',               'Cancel running scans',                        'scans'),
    -- targets
    ('targets.read',               'Read scan targets',                           'targets'),
    ('targets.manage',             'Create/update/delete scan targets',           'targets'),
    -- projects
    ('projects.read',              'Read projects',                               'projects'),
    ('projects.manage',            'Create/update projects',                      'projects'),
    -- organizations
    ('organizations.read',         'Read organizations',                          'organizations'),
    ('organizations.manage',       'Create/update organizations',                 'organizations'),
    -- teams
    ('teams.read',                 'Read teams and members',                      'teams'),
    ('teams.manage',               'Create teams, manage membership',             'teams'),
    -- auth profiles (DAST credentials)
    ('authprofiles.read',          'Read DAST auth profiles',                     'authprofiles'),
    ('authprofiles.manage',        'Create/update/delete DAST auth profiles',     'authprofiles'),
    -- artifacts (SAST source uploads)
    ('artifacts.read',             'Read source artifacts',                       'artifacts'),
    ('artifacts.manage',           'Upload/delete source artifacts',              'artifacts'),
    -- governance
    ('governance.approvals.read',  'Read approval requests',                      'governance'),
    ('governance.approvals.decide','Approve or reject approval requests',         'governance'),
    ('governance.estop.activate',  'Activate emergency stop',                     'governance'),
    ('governance.estop.lift',      'Lift emergency stop',                         'governance'),
    ('governance.estop.read',      'Read active emergency stops',                 'governance'),
    -- settings
    ('settings.read',              'Read org settings',                           'settings'),
    ('settings.manage',            'Modify org settings',                         'settings'),
    -- users
    ('users.read',                 'List users',                                  'users'),
    ('users.manage',               'Create/update/delete users, change roles',    'users'),
    -- api_keys
    ('api_keys.read',              'List API keys',                               'api_keys'),
    ('api_keys.manage',            'Create/rotate/revoke API keys',               'api_keys'),
    -- sso (Phase 3 uses this)
    ('sso.manage',                 'Configure SSO providers + group mappings',    'sso'),
    -- audit
    ('audit.read',                 'Read audit log',                              'audit'),
    -- webhooks
    ('webhooks.read',              'Read webhook configs',                        'webhooks'),
    ('webhooks.manage',            'Create/update/delete/test webhook configs',   'webhooks'),
    -- retention
    ('retention.read',             'Read retention policies + records',           'retention'),
    ('retention.manage',           'Update retention policies',                   'retention'),
    -- reports
    ('reports.read',               'Read aggregate reports',                      'reports'),
    -- surface (attack surface inventory)
    ('surface.read',               'Read attack surface entries + stats',         'surface'),
    -- notifications (per-user; read-only user view)
    ('notifications.read',         'Read own notifications',                      'notifications'),
    -- ops (platform-level observability)
    ('ops.read',                   'Read platform ops metrics',                   'ops');

-- ── Seed: role_permissions ──────────────────────────────────────
-- owner: everything
INSERT INTO auth.role_permissions (role_id, permission_id)
    SELECT 'owner', id FROM auth.permissions;

-- admin: everything except users.manage
INSERT INTO auth.role_permissions (role_id, permission_id)
    SELECT 'admin', id FROM auth.permissions WHERE id <> 'users.manage';

-- security_engineer: operational work, no settings/users/keys/sso/org/retention
INSERT INTO auth.role_permissions (role_id, permission_id) VALUES
    ('security_engineer','risks.read'),
    ('security_engineer','risks.resolve'),
    ('security_engineer','risks.mute'),
    ('security_engineer','risks.reopen'),
    ('security_engineer','risks.acknowledge'),
    ('security_engineer','risks.rebuild'),
    ('security_engineer','findings.read'),
    ('security_engineer','findings.triage'),
    ('security_engineer','scans.read'),
    ('security_engineer','scans.run'),
    ('security_engineer','scans.cancel'),
    ('security_engineer','targets.read'),
    ('security_engineer','targets.manage'),
    ('security_engineer','projects.read'),
    ('security_engineer','organizations.read'),
    ('security_engineer','teams.read'),
    ('security_engineer','authprofiles.read'),
    ('security_engineer','authprofiles.manage'),
    ('security_engineer','artifacts.read'),
    ('security_engineer','artifacts.manage'),
    ('security_engineer','governance.approvals.read'),
    ('security_engineer','governance.estop.activate'),
    ('security_engineer','governance.estop.read'),
    ('security_engineer','settings.read'),
    ('security_engineer','audit.read'),
    ('security_engineer','webhooks.read'),
    ('security_engineer','reports.read'),
    ('security_engineer','surface.read'),
    ('security_engineer','notifications.read');

-- auditor: read-only everywhere (incl. audit log)
INSERT INTO auth.role_permissions (role_id, permission_id) VALUES
    ('auditor','risks.read'),
    ('auditor','findings.read'),
    ('auditor','scans.read'),
    ('auditor','targets.read'),
    ('auditor','projects.read'),
    ('auditor','organizations.read'),
    ('auditor','teams.read'),
    ('auditor','authprofiles.read'),
    ('auditor','artifacts.read'),
    ('auditor','governance.approvals.read'),
    ('auditor','governance.estop.read'),
    ('auditor','settings.read'),
    ('auditor','users.read'),
    ('auditor','api_keys.read'),
    ('auditor','audit.read'),
    ('auditor','webhooks.read'),
    ('auditor','retention.read'),
    ('auditor','reports.read'),
    ('auditor','surface.read'),
    ('auditor','notifications.read');

-- developer: least privilege
INSERT INTO auth.role_permissions (role_id, permission_id) VALUES
    ('developer','risks.read'),
    ('developer','risks.acknowledge'),
    ('developer','findings.read'),
    ('developer','scans.read'),
    ('developer','targets.read'),
    ('developer','projects.read'),
    ('developer','notifications.read');

COMMIT;
```

- [ ] **Step 2: Write the down migration**

File: `migrations/024_rbac_tables.down.sql`:

```sql
BEGIN;
DROP TABLE IF EXISTS auth.role_permissions;
DROP TABLE IF EXISTS auth.permissions;
DROP TABLE IF EXISTS auth.roles;
COMMIT;
```

- [ ] **Step 3: Apply up migration against local DB + verify**

Run:
```bash
psql "$DATABASE_URL" -f migrations/024_rbac_tables.up.sql
psql "$DATABASE_URL" -c "SELECT count(*) FROM auth.roles;"          # expect 5
psql "$DATABASE_URL" -c "SELECT count(*) FROM auth.permissions;"    # expect 41
psql "$DATABASE_URL" -c "SELECT count(*) FROM auth.role_permissions;"  # expect 41 + 40 + 29 + 20 + 7 = 137
```
Expected: exit 0, counts match.

- [ ] **Step 4: Verify down migration restores clean state**

Run:
```bash
psql "$DATABASE_URL" -f migrations/024_rbac_tables.down.sql
psql "$DATABASE_URL" -c "SELECT count(*) FROM auth.roles;"   # expect error: relation does not exist
```

- [ ] **Step 5: Re-apply up (leave applied for subsequent tasks)**

Run: `psql "$DATABASE_URL" -f migrations/024_rbac_tables.up.sql`

- [ ] **Step 6: Commit**

```bash
git add migrations/024_rbac_tables.up.sql migrations/024_rbac_tables.down.sql
git commit -m "feat(auth): add RBAC tables and seed 5 roles + 27 permissions"
```

### Task 1.2: Role rename migration

**Files:**
- Create: `migrations/025_users_role_rename.up.sql`
- Create: `migrations/025_users_role_rename.down.sql`

- [ ] **Step 1: Write the up migration**

File: `migrations/025_users_role_rename.up.sql`:

```sql
BEGIN;

ALTER TABLE core.users DROP CONSTRAINT IF EXISTS users_role_check;

UPDATE core.users SET role = 'owner'             WHERE role = 'platform_admin';
UPDATE core.users SET role = 'admin'             WHERE role = 'security_admin';
UPDATE core.users SET role = 'security_engineer' WHERE role = 'appsec_analyst';
-- auditor unchanged.

ALTER TABLE core.users ADD CONSTRAINT users_role_check
    CHECK (role IN ('owner', 'admin', 'security_engineer', 'auditor', 'developer'));

-- Belt-and-braces FK: role must exist in auth.roles.
ALTER TABLE core.users ADD CONSTRAINT users_role_fkey
    FOREIGN KEY (role) REFERENCES auth.roles(id) ON UPDATE CASCADE ON DELETE RESTRICT;

COMMIT;
```

- [ ] **Step 2: Write the down migration (safe, non-destructive)**

File: `migrations/025_users_role_rename.down.sql`:

```sql
-- SAFE DOWN MIGRATION
-- This migration is FAIL-CLOSED: it refuses to run if the rollback would
-- lose data. Specifically:
--   1. Refuses if any user has role='developer' (no pre-migration equivalent).
--   2. Refuses if any user has been created AFTER the up migration ran
--      (new admin/owner users created post-migration cannot be safely reverted
--      because we cannot tell whether they were created as 'admin' or upgraded
--      from 'security_admin').
--
-- To force rollback anyway (data loss acceptable), set the session var
--   SET sentinelcore.force_role_downgrade = 'yes';
-- before running this script.

BEGIN;

DO $$
DECLARE
    dev_count INT;
    post_migration_count INT;
    force_flag TEXT;
    up_migration_at TIMESTAMPTZ;
BEGIN
    -- How many users have the new 'developer' role?
    SELECT count(*) INTO dev_count FROM core.users WHERE role = 'developer';

    -- Record the up-migration timestamp via the schema_migrations table that
    -- golang-migrate writes, or fall back to the oldest timestamp we find.
    -- Adjust table name if your migration tool uses a different one.
    SELECT COALESCE(
        (SELECT applied_at FROM schema_migrations WHERE version = '025'),
        now() - interval '1 year'
    ) INTO up_migration_at;

    SELECT count(*) INTO post_migration_count
    FROM core.users
    WHERE created_at > up_migration_at
      AND role IN ('owner', 'admin');

    SELECT current_setting('sentinelcore.force_role_downgrade', true) INTO force_flag;

    IF (dev_count > 0 OR post_migration_count > 0) AND force_flag IS DISTINCT FROM 'yes' THEN
        RAISE EXCEPTION
            'Refusing to downgrade: % developer-role users and % post-migration owner/admin users exist. '
            'Downgrade would either delete developers or misclassify admins. '
            'Set sentinelcore.force_role_downgrade = ''yes'' to proceed with data loss.',
            dev_count, post_migration_count;
    END IF;
END $$;

ALTER TABLE core.users DROP CONSTRAINT IF EXISTS users_role_fkey;
ALTER TABLE core.users DROP CONSTRAINT IF EXISTS users_role_check;

-- Reverse the role rename. Only safe because the guard above ensures
-- no new-vocabulary-only users exist (or force_flag=yes accepts loss).
UPDATE core.users SET role = 'platform_admin' WHERE role = 'owner';
UPDATE core.users SET role = 'security_admin' WHERE role = 'admin';
UPDATE core.users SET role = 'appsec_analyst' WHERE role = 'security_engineer';

-- Only delete developers if force flag is set (the guard above let us through).
DELETE FROM core.users WHERE role = 'developer';

ALTER TABLE core.users ADD CONSTRAINT users_role_check
    CHECK (role IN ('platform_admin', 'security_admin', 'appsec_analyst', 'auditor'));

COMMIT;
```

> **Note on rollback strategy:** once this migration ships and any `developer` user is created, rollback is a **data-loss event**. The project's intended rollback path is *roll forward with a fix*, not *roll back*. The fail-closed guard exists only to prevent accidental data destruction during early-production incidents, not as a supported downgrade path.

- [ ] **Step 3: Apply + verify**

Run:
```bash
psql "$DATABASE_URL" -f migrations/025_users_role_rename.up.sql
psql "$DATABASE_URL" -c "SELECT role, count(*) FROM core.users GROUP BY role;"
```
Expected: only new role names appear.

- [ ] **Step 4: Commit**

```bash
git add migrations/025_users_role_rename.up.sql migrations/025_users_role_rename.down.sql
git commit -m "feat(auth): rename user roles to owner/admin/security_engineer/auditor/developer"
```

---

## Chunk 2: RBAC Cache

### Task 2.1: Define cache types + constructor

**Files:**
- Create: `internal/policy/cache.go`
- Create: `internal/policy/cache_test.go`

- [ ] **Step 1: Write the failing test**

File: `internal/policy/cache_test.go`:

```go
package policy

import (
	"context"
	"testing"
)

func TestCache_CanFalseBeforeLoad(t *testing.T) {
	c := NewCache()
	if c.Can("owner", "risks.read") {
		t.Fatal("expected false before Reload")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestCache_CanFalseBeforeLoad -v`
Expected: FAIL with "undefined: NewCache"

- [ ] **Step 3: Write minimal implementation**

File: `internal/policy/cache.go`:

```go
package policy

import (
	"context"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Cache holds the role→permission matrix in memory. Loaded at startup,
// refreshed via pg_notify when an admin mutates role_permissions.
//
// Readers acquire RLock; full reload swaps the map atomically under Lock,
// so readers never see a partial state.
type Cache struct {
	mu       sync.RWMutex
	matrix   map[string]map[string]struct{} // role_id → set of permission_id
	allPerms map[string]struct{}             // set of every known permission_id
	version  int64                           // incremented each Reload
}

// NewCache returns an empty cache. Call Reload before serving traffic.
func NewCache() *Cache {
	return &Cache{
		matrix:   make(map[string]map[string]struct{}),
		allPerms: make(map[string]struct{}),
	}
}

// Can returns true iff the role has the permission. Safe for concurrent use.
// Returns false for unknown roles or permissions.
func (c *Cache) Can(role, perm string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	perms, ok := c.matrix[role]
	if !ok {
		return false
	}
	_, ok = perms[perm]
	return ok
}

// HasPermission returns true iff perm exists in the permissions catalog
// (regardless of any role). Used at key-creation time to validate scopes.
func (c *Cache) HasPermission(perm string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.allPerms[perm]
	return ok
}

// Reload replaces the in-memory matrix from the database in a single
// atomic swap. Safe to call concurrently with readers.
func (c *Cache) Reload(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT rp.role_id, rp.permission_id
		FROM auth.role_permissions rp
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	newMatrix := make(map[string]map[string]struct{})
	for rows.Next() {
		var roleID, permID string
		if err := rows.Scan(&roleID, &permID); err != nil {
			return err
		}
		if _, ok := newMatrix[roleID]; !ok {
			newMatrix[roleID] = make(map[string]struct{})
		}
		newMatrix[roleID][permID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Load the full permissions catalog separately (there may be permissions
	// with zero role assignments that we still want to recognise).
	permRows, err := pool.Query(ctx, `SELECT id FROM auth.permissions`)
	if err != nil {
		return err
	}
	defer permRows.Close()
	newAll := make(map[string]struct{})
	for permRows.Next() {
		var id string
		if err := permRows.Scan(&id); err != nil {
			return err
		}
		newAll[id] = struct{}{}
	}
	if err := permRows.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	c.matrix = newMatrix
	c.allPerms = newAll
	c.version++
	c.mu.Unlock()
	return nil
}

// Version returns the current reload counter. Used in tests.
func (c *Cache) Version() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/ -run TestCache_CanFalseBeforeLoad -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/cache.go internal/policy/cache_test.go
git commit -m "feat(policy): add RBAC cache with atomic reload"
```

### Task 2.2: Reload integration test

**Files:**
- Modify: `internal/policy/cache_test.go`

- [ ] **Step 1: Add test that loads real data via the pool**

Append to `internal/policy/cache_test.go`:

```go
func TestCache_ReloadMatchesDB(t *testing.T) {
	pool := testPool(t) // helper that connects to TEST_DATABASE_URL; skip if unset
	c := NewCache()
	if err := c.Reload(context.Background(), pool); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !c.Can("owner", "users.manage") {
		t.Fatal("owner should have users.manage")
	}
	if c.Can("admin", "users.manage") {
		t.Fatal("admin must NOT have users.manage")
	}
	if !c.Can("developer", "risks.read") {
		t.Fatal("developer should have risks.read")
	}
	if c.Can("developer", "scans.run") {
		t.Fatal("developer must NOT have scans.run")
	}
	if !c.HasPermission("scans.run") {
		t.Fatal("HasPermission should return true for known permission")
	}
	if c.HasPermission("nonexistent.perm") {
		t.Fatal("HasPermission should return false for unknown")
	}
}
```

- [ ] **Step 2: Add testPool helper**

Create `internal/policy/testing_test.go`:

```go
package policy

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
```

- [ ] **Step 3: Run and verify**

Run:
```bash
TEST_DATABASE_URL="$DATABASE_URL" go test ./internal/policy/ -run TestCache_ReloadMatchesDB -v
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/policy/cache_test.go internal/policy/testing_test.go
git commit -m "test(policy): verify cache Reload against seeded DB"
```

### Task 2.3: Concurrent-read safety test

**Files:**
- Modify: `internal/policy/cache_test.go`

- [ ] **Step 1: Add race test**

Append:

```go
func TestCache_ConcurrentReadDuringReload(t *testing.T) {
	pool := testPool(t)
	c := NewCache()
	if err := c.Reload(context.Background(), pool); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			_ = c.Can("owner", "risks.read")
		}
		close(done)
	}()
	for i := 0; i < 20; i++ {
		if err := c.Reload(context.Background(), pool); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
```

- [ ] **Step 2: Run with race detector**

Run: `TEST_DATABASE_URL="$DATABASE_URL" go test -race ./internal/policy/ -run TestCache_ConcurrentReadDuringReload -v`
Expected: PASS, no race detected.

- [ ] **Step 3: Commit**

```bash
git add internal/policy/cache_test.go
git commit -m "test(policy): verify cache is race-free under concurrent reload"
```

---

## Chunk 3: Principal Abstraction

### Task 3.1: Define Principal + context helpers

**Files:**
- Create: `pkg/auth/principal.go`
- Create: `pkg/auth/principal_test.go`

- [ ] **Step 1: Write the failing test**

File: `pkg/auth/principal_test.go`:

```go
package auth

import (
	"context"
	"testing"
)

func TestPrincipalContext_RoundTrip(t *testing.T) {
	p := Principal{
		Kind:   "user",
		OrgID:  "org-123",
		UserID: "user-456",
		Role:   "admin",
	}
	ctx := WithPrincipal(context.Background(), p)

	got, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("expected principal in context")
	}
	if got.UserID != "user-456" {
		t.Fatalf("want user-456, got %s", got.UserID)
	}
}

func TestPrincipalFromContext_Empty(t *testing.T) {
	_, ok := PrincipalFromContext(context.Background())
	if ok {
		t.Fatal("expected no principal")
	}
}
```

- [ ] **Step 2: Run test (fails)**

Run: `go test ./pkg/auth/ -run TestPrincipalContext -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

File: `pkg/auth/principal.go`:

```go
package auth

import (
	"context"
	"slices"
)

// Principal is the authenticated identity behind a request. Exactly one
// Principal exists per authenticated request; handlers read it via
// PrincipalFromContext.
//
// Kind is either "user" (JWT-authenticated) or "api_key" (sc_... token).
// Users resolve permissions through Role → RBAC cache; API keys carry
// their own Scopes list.
type Principal struct {
	Kind   string   // "user" | "api_key"
	OrgID  string
	UserID string   // empty for tenant-owned service accounts
	Role   string   // empty for api_key
	Scopes []string // empty for user
	KeyID  string   // empty for user
	JTI    string   // empty for api_key
}

// PermissionChecker abstracts the RBAC cache so middleware/tests can
// inject a fake without pulling the pgxpool dependency.
type PermissionChecker interface {
	Can(role, perm string) bool
}

// Can returns true iff this principal is allowed to perform the given
// permission. For users, delegates to the RBAC cache. For API keys,
// checks the embedded scopes list.
func (p Principal) Can(perm string, cache PermissionChecker) bool {
	switch p.Kind {
	case "user":
		if cache == nil {
			return false
		}
		return cache.Can(p.Role, perm)
	case "api_key":
		return slices.Contains(p.Scopes, perm)
	default:
		return false
	}
}

type principalKey struct{}

// WithPrincipal returns a child context carrying the principal.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext extracts the principal, if any.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
```

- [ ] **Step 4: Run test (passes)**

Run: `go test ./pkg/auth/ -run TestPrincipalContext -v`
Expected: PASS.

- [ ] **Step 5: Test Principal.Can for both kinds**

Append to `pkg/auth/principal_test.go`:

```go
type fakeChecker map[string]map[string]struct{}

func (f fakeChecker) Can(role, perm string) bool {
	p, ok := f[role]
	if !ok {
		return false
	}
	_, ok = p[perm]
	return ok
}

func TestPrincipal_Can_User(t *testing.T) {
	checker := fakeChecker{"admin": {"scans.run": {}}}

	p := Principal{Kind: "user", Role: "admin"}
	if !p.Can("scans.run", checker) {
		t.Fatal("admin should have scans.run via checker")
	}
	if p.Can("users.manage", checker) {
		t.Fatal("admin should NOT have users.manage")
	}
}

func TestPrincipal_Can_APIKey(t *testing.T) {
	p := Principal{Kind: "api_key", Scopes: []string{"risks.read", "scans.read"}}
	if !p.Can("risks.read", nil) {
		t.Fatal("key with risks.read scope should allow")
	}
	if p.Can("scans.run", nil) {
		t.Fatal("key without scans.run scope should deny")
	}
}

func TestPrincipal_Can_UnknownKind(t *testing.T) {
	p := Principal{Kind: "weird"}
	if p.Can("anything", fakeChecker{}) {
		t.Fatal("unknown kind must deny")
	}
}
```

- [ ] **Step 6: Run and verify**

Run: `go test ./pkg/auth/ -run TestPrincipal -v`
Expected: PASS for all.

- [ ] **Step 7: Commit**

```bash
git add pkg/auth/principal.go pkg/auth/principal_test.go
git commit -m "feat(auth): add Principal abstraction with permission check"
```

---

## Chunk 4: compatMode JWT Translator

### Task 4.1: Add role translator to ValidateToken

**Files:**
- Modify: `pkg/auth/jwt.go`
- Modify: `pkg/auth/jwt_test.go`

- [ ] **Step 1: Read current jwt.go ValidateToken**

Run: `sed -n '1,120p' pkg/auth/jwt.go`
Identify where `Claims` is returned after signature + expiry verification — that's the insertion point.

- [ ] **Step 2: Write the failing test**

Append to `pkg/auth/jwt_test.go`:

```go
func TestValidateToken_CompatModeTranslatesOldRoles(t *testing.T) {
	mgr := newTestJWTManager(t)
	cases := []struct {
		oldRole string
		wantNew string
	}{
		{"platform_admin", "owner"},
		{"security_admin", "admin"},
		{"appsec_analyst", "security_engineer"},
		{"auditor", "auditor"},         // unchanged
		{"developer", "developer"},     // already new
	}
	for _, tc := range cases {
		t.Run(tc.oldRole, func(t *testing.T) {
			tok, err := mgr.IssueAccessToken("user-1", "org-1", tc.oldRole)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := mgr.ValidateToken(tok)
			if err != nil {
				t.Fatal(err)
			}
			if claims.Role != tc.wantNew {
				t.Fatalf("role=%q, want %q", claims.Role, tc.wantNew)
			}
		})
	}
}
```

(Assumes `newTestJWTManager` exists — if not, copy from existing jwt_test.go helpers.)

- [ ] **Step 3: Run test (fails)**

Run: `go test ./pkg/auth/ -run TestValidateToken_CompatModeTranslatesOldRoles -v`
Expected: FAIL — translation not implemented.

- [ ] **Step 4: Implement the translator**

In `pkg/auth/jwt.go`, add package-level map above the `JWTManager` type:

```go
// compatRoleMap translates pre-migration role strings to the new vocabulary.
// This is the SINGLE chokepoint for legacy role handling — no other code
// in the codebase should see or handle old role names. Remove this map
// and the translateRole call 14 days after the role-rename migration ships.
var compatRoleMap = map[string]string{
	"platform_admin": "owner",
	"security_admin": "admin",
	"appsec_analyst": "security_engineer",
	// auditor is unchanged — no entry needed (identity translation).
}

// translateLegacyRole maps an old role string to the new vocabulary.
// Returns the input unchanged if no mapping exists (new roles, auditor).
func translateLegacyRole(role string) string {
	if mapped, ok := compatRoleMap[role]; ok {
		return mapped
	}
	return role
}
```

At the very end of `ValidateToken`, **after** the returned claims are populated and **before** the final `return claims, nil`:

```go
claims.Role = translateLegacyRole(claims.Role)
return claims, nil
```

- [ ] **Step 5: Run test (passes)**

Run: `go test ./pkg/auth/ -run TestValidateToken_CompatModeTranslatesOldRoles -v`
Expected: PASS.

- [ ] **Step 6: Run full jwt test suite to verify no regressions**

Run: `go test ./pkg/auth/ -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/auth/jwt.go pkg/auth/jwt_test.go
git commit -m "feat(auth): translate legacy role strings in ValidateToken (compat mode)"
```

---

## Chunk 5: RequirePermission Middleware

### Task 5.1: Build the middleware decorator

**Files:**
- Create: `pkg/auth/require_permission.go`
- Create: `pkg/auth/require_permission_test.go`

- [ ] **Step 1: Write the failing test**

File: `pkg/auth/require_permission_test.go`:

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type countingChecker struct {
	allowed map[string]map[string]struct{}
}

func (c countingChecker) Can(role, perm string) bool {
	p, ok := c.allowed[role]
	if !ok {
		return false
	}
	_, ok = p[perm]
	return ok
}

func TestRequirePermission_AllowsWhenPrincipalHasPermission(t *testing.T) {
	checker := countingChecker{allowed: map[string]map[string]struct{}{
		"admin": {"scans.run": {}},
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	mw := RequirePermission("scans.run", checker, nil)(next)

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "user", Role: "admin", UserID: "u1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
}

func TestRequirePermission_DeniesWhenPrincipalLacksPermission(t *testing.T) {
	checker := countingChecker{allowed: map[string]map[string]struct{}{
		"developer": {"risks.read": {}},
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	mw := RequirePermission("users.manage", checker, nil)(next)

	req := httptest.NewRequest("DELETE", "/api/v1/users/x", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "user", Role: "developer", UserID: "u1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler must not be called on deny")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"code":"FORBIDDEN"`) {
		t.Fatalf("body missing FORBIDDEN code: %s", rec.Body.String())
	}
}

func TestRequirePermission_DeniesWhenNoPrincipal(t *testing.T) {
	checker := countingChecker{}
	mw := RequirePermission("scans.run", checker, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called")
	}))
	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

func TestRequirePermission_APIKeyWithScope(t *testing.T) {
	mw := RequirePermission("findings.read", countingChecker{}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "api_key", Scopes: []string{"findings.read", "scans.read"},
		KeyID: "k1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (key has scope)", rec.Code)
	}
}

func TestRequirePermission_APIKeyMissingScope(t *testing.T) {
	mw := RequirePermission("scans.run", countingChecker{}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("next must not be called")
		}))

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "api_key", Scopes: []string{"findings.read"},
		KeyID: "k1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "INSUFFICIENT_SCOPE") {
		t.Fatalf("body missing INSUFFICIENT_SCOPE: %s", rec.Body.String())
	}
}
```

- [ ] **Step 2: Implement**

File: `pkg/auth/require_permission.go`:

```go
package auth

import (
	"context"
	"encoding/json"
	"net/http"
)

// AuditDenier is invoked when a request is denied by RequirePermission.
// Kept as an interface so tests can inject a fake without pulling the
// pkg/audit NATS dependency.
type AuditDenier interface {
	EmitAuthzDenied(ctx context.Context, p Principal, required string)
}

// RequirePermission wraps an http.Handler, enforcing that the request's
// Principal has the named permission. On deny it returns 403 FORBIDDEN
// (or INSUFFICIENT_SCOPE for API keys) and emits an audit event.
//
// If no Principal is in the context, returns 401 UNAUTHENTICATED. This
// should not normally happen because AuthenticateMiddleware runs first,
// but the check keeps RequirePermission safe to compose in any order.
func RequirePermission(required string, checker PermissionChecker, denier AuditDenier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok {
				writeErr(w, http.StatusUnauthorized, "authentication required", "UNAUTHENTICATED")
				return
			}
			if p.Can(required, checker) {
				next.ServeHTTP(w, r)
				return
			}
			if denier != nil {
				denier.EmitAuthzDenied(r.Context(), p, required)
			}
			if p.Kind == "api_key" {
				writeErr(w, http.StatusForbidden, "missing scope: "+required, "INSUFFICIENT_SCOPE")
				return
			}
			writeErr(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		})
	}
}

func writeErr(w http.ResponseWriter, status int, msg, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
		"code":  code,
	})
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./pkg/auth/ -run TestRequirePermission -v`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add pkg/auth/require_permission.go pkg/auth/require_permission_test.go
git commit -m "feat(auth): add RequirePermission middleware decorator"
```

### Task 5.2: Audit denier implementation

**Files:**
- Modify: `pkg/audit/emitter.go` (add method)
- Create: `pkg/audit/authz_denier.go`

- [ ] **Step 1: Inspect existing emitter**

Run: `grep -n "func.*Emit" pkg/audit/emitter.go`
Confirm the existing `Emit(ctx, AuditEvent)` signature.

- [ ] **Step 2: Write the denier wrapper**

File: `pkg/audit/authz_denier.go`:

```go
package audit

import (
	"context"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// AuthzDenier implements auth.AuditDenier by emitting an AuditEvent
// for every permission denial.
type AuthzDenier struct {
	e *Emitter
}

// NewAuthzDenier wraps an existing Emitter.
func NewAuthzDenier(e *Emitter) *AuthzDenier {
	return &AuthzDenier{e: e}
}

// EmitAuthzDenied implements auth.AuditDenier.
func (d *AuthzDenier) EmitAuthzDenied(ctx context.Context, p auth.Principal, required string) {
	_ = d.e.Emit(ctx, AuditEvent{
		ActorType:    p.Kind,
		ActorID:      p.UserID, // empty for tenant-owned service-account keys
		Action:       "authz.denied",
		ResourceType: "permission",
		ResourceID:   required,
		OrgID:        p.OrgID,
		Result:       "failure",
		Details: map[string]any{
			"required":  required,
			"key_id":    p.KeyID,
			"role":      p.Role,
			"scopes":    p.Scopes,
		},
	})
}
```

- [ ] **Step 3: Add end-to-end denier test**

The `RequirePermission` middleware in Task 5.1 accepts an `AuditDenier` interface. Task 5.1's tests cover the HTTP allow/deny behavior with a nil denier. This step verifies the denier is actually invoked exactly once per denial, with the right arguments, when one is provided.

Create `pkg/auth/require_permission_denier_test.go`:

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// spyDenier records every EmitAuthzDenied call so the test can assert.
type spyDenier struct {
	calls []spyDenierCall
}
type spyDenierCall struct {
	Principal Principal
	Required  string
}

func (s *spyDenier) EmitAuthzDenied(_ context.Context, p Principal, required string) {
	s.calls = append(s.calls, spyDenierCall{Principal: p, Required: required})
}

func TestRequirePermission_EmitsDenierOnDeny(t *testing.T) {
	spy := &spyDenier{}
	checker := countingChecker{} // empty — everything denies
	mw := RequirePermission("scans.run", checker, spy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run on deny")
	}))

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "user", Role: "developer", UserID: "u1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
	if len(spy.calls) != 1 {
		t.Fatalf("denier called %d times, want 1", len(spy.calls))
	}
	if spy.calls[0].Required != "scans.run" {
		t.Fatalf("required=%q want scans.run", spy.calls[0].Required)
	}
	if spy.calls[0].Principal.UserID != "u1" {
		t.Fatalf("principal.UserID=%q want u1", spy.calls[0].Principal.UserID)
	}
}

func TestRequirePermission_DoesNotEmitDenierOnAllow(t *testing.T) {
	spy := &spyDenier{}
	checker := countingChecker{allowed: map[string]map[string]struct{}{
		"admin": {"scans.run": {}},
	}}
	mw := RequirePermission("scans.run", checker, spy)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "user", Role: "admin",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if len(spy.calls) != 0 {
		t.Fatalf("denier should not be called on allow; got %d calls", len(spy.calls))
	}
}

func TestRequirePermission_EmitsDenierForAPIKeyMissingScope(t *testing.T) {
	spy := &spyDenier{}
	mw := RequirePermission("scans.run", countingChecker{}, spy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not run")
	}))

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "api_key", KeyID: "k1", OrgID: "o1",
		Scopes: []string{"findings.read"}, // lacks scans.run
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
	if len(spy.calls) != 1 {
		t.Fatalf("denier called %d times, want 1", len(spy.calls))
	}
	if spy.calls[0].Principal.Kind != "api_key" {
		t.Fatalf("kind=%q want api_key", spy.calls[0].Principal.Kind)
	}
	if spy.calls[0].Principal.KeyID != "k1" {
		t.Fatalf("key_id=%q want k1", spy.calls[0].Principal.KeyID)
	}
}
```

- [ ] **Step 4: Run the denier tests**

Run: `go test ./pkg/auth/ -run "TestRequirePermission_Emits|TestRequirePermission_DoesNotEmit" -v`
Expected: all three PASS.

- [ ] **Step 5: Verify build**

Run: `go build ./...`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add pkg/audit/authz_denier.go pkg/auth/require_permission_denier_test.go
git commit -m "feat(audit): add AuthzDenier wrapper + verify emitter invocation"
```

> **Wiring note:** the denier is not yet installed into the middleware chain — that happens in Task 7.1 (`s.denier = audit.NewAuthzDenier(opts.AuditEmitter)`). Until then, routes that pass a nil denier are tested only for HTTP behavior, which Task 5.1 covers.

---

## Chunk 6: Authenticate Middleware Update

### Task 6.1: Rewrite middleware to produce Principal

**Files:**
- Modify: `pkg/auth/middleware.go`

- [ ] **Step 1: Read current middleware.go**

Run: `cat pkg/auth/middleware.go`
Note the existing `UserContext` type, `userContextKey`, and the AuthMiddleware flow.

- [ ] **Step 2: Extend AuthMiddleware to set both UserContext and Principal (transitional)**

In `pkg/auth/middleware.go`, modify `AuthMiddleware` so that after resolving the user or API key, it constructs a `Principal` and stores it via `WithPrincipal` **in addition to** the existing `UserContext`. This keeps old handlers working until Task 7.x migrates them.

Target edit inside the user-JWT branch (after JWT validated):

```go
p := Principal{
    Kind:   "user",
    OrgID:  claims.OrgID,
    UserID: claims.Subject,
    Role:   claims.Role, // already translated by compatMode in jwt.go
    JTI:    claims.ID,
}
ctx = WithPrincipal(ctx, p)
// keep existing: ctx = context.WithValue(ctx, userContextKey{}, userCtx)
```

And inside the API-key branch (after `apikeys.Resolve`):

```go
p := Principal{
    Kind:   "api_key",
    OrgID:  resolved.OrgID,
    UserID: resolved.UserID, // may be empty for service accounts (after Phase 2)
    Scopes: resolved.Scopes,
    KeyID:  resolved.KeyID,
}
ctx = WithPrincipal(ctx, p)
// keep existing UserContext population for backward compat
```

- [ ] **Step 3: Add tests that Principal is populated for both auth paths**

Append to a new file `pkg/auth/middleware_principal_test.go`:

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeJWTValidator is the minimal interface the middleware needs from
// the JWT manager. AuthMiddleware's real implementation calls
// mgr.ValidateToken(token) to obtain Claims. We stub it here so the
// test needs no real RSA keys.
type fakeJWTValidator struct {
	claims *Claims
	err    error
}

func (f *fakeJWTValidator) ValidateToken(_ string) (*Claims, error) {
	return f.claims, f.err
}

// fakeAPIKeyResolver returns a fixed ResolvedKey for any token.
type fakeAPIKeyResolver struct {
	resolved *APIKeyResolved
	err      error
}

func (f *fakeAPIKeyResolver) Resolve(_ context.Context, _ string) (*APIKeyResolved, error) {
	return f.resolved, f.err
}

func TestAuthMiddleware_PopulatesPrincipal_ForUserJWT(t *testing.T) {
	mw := NewAuthMiddleware(AuthMiddlewareOptions{
		JWT: &fakeJWTValidator{claims: &Claims{
			// Subject set via RegisteredClaims.Subject in real code;
			// the fake exposes whatever fields middleware reads.
			OrgID: "org-1", Role: "admin",
		}},
		// nil sessionStore ok if the test path doesn't require idle check;
		// adjust to your actual middleware constructor.
	})

	var got Principal
	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/risks", nil)
	req.Header.Set("Authorization", "Bearer some-jwt")
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if !ok {
		t.Fatal("Principal not set in context")
	}
	if got.Kind != "user" || got.Role != "admin" || got.OrgID != "org-1" {
		t.Fatalf("principal=%+v", got)
	}
}

func TestAuthMiddleware_PopulatesPrincipal_ForAPIKey(t *testing.T) {
	mw := NewAuthMiddleware(AuthMiddlewareOptions{
		APIKeys: &fakeAPIKeyResolver{resolved: &APIKeyResolved{
			KeyID: "k1", OrgID: "org-1", UserID: "u1",
			Scopes: []string{"risks.read", "scans.read"},
		}},
	})

	var got Principal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/risks", nil)
	req.Header.Set("Authorization", "Bearer sc_fakeplaceholder")
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if got.Kind != "api_key" || got.KeyID != "k1" {
		t.Fatalf("principal=%+v", got)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("scopes=%v", got.Scopes)
	}
}
```

> **Note:** the exact constructor names (`NewAuthMiddleware`, `AuthMiddlewareOptions`, `APIKeyResolved`) must match the existing code in `pkg/auth/middleware.go`. If they differ, rename them here — the point is that both auth paths populate `Principal` and the test exercises both without real crypto or DB.

- [ ] **Step 4: Run the new tests**

Run: `go test ./pkg/auth/ -run TestAuthMiddleware_PopulatesPrincipal -v`
Expected: PASS for both.

- [ ] **Step 5: Run full middleware test suite to check for regressions**

Run: `go test ./pkg/auth/ -v`
Expected: all existing tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/auth/middleware.go pkg/auth/middleware_principal_test.go
git commit -m "feat(auth): populate Principal in AuthMiddleware alongside UserContext"
```

---

## Chunk 7: Server Wiring + /auth/me + Route Migration

### Task 7.1: Initialize cache + denier at startup

**Files:**
- Modify: `cmd/controlplane/main.go`
- Modify: `internal/controlplane/server.go`

- [ ] **Step 1: Read current startup flow**

Run: `grep -n "policy\|cache" cmd/controlplane/main.go internal/controlplane/server.go | head -20`

- [ ] **Step 2: Add cache init before server starts**

In `cmd/controlplane/main.go`, after the pgxpool is created and before the server starts:

```go
cache := policy.NewCache()
if err := cache.Reload(ctx, pool); err != nil {
    log.Fatal("rbac cache init: " + err.Error())
}
// Pass cache + audit emitter to server.
srv := controlplane.NewServer(controlplane.Options{
    Pool:         pool,
    JWTManager:   jwtMgr,
    SessionStore: sessStore,
    RBACCache:    cache,
    AuditEmitter: auditEmitter,
    // ... existing fields
})
```

Adjust `controlplane.Options` in `internal/controlplane/server.go` to carry `RBACCache *policy.Cache` and `AuditEmitter *audit.Emitter`.

- [ ] **Step 3: Expose denier in Server**

In `internal/controlplane/server.go`, add a field `denier auth.AuditDenier` populated from `audit.NewAuthzDenier(opts.AuditEmitter)`.

- [ ] **Step 4: Verify build**

Run: `go build ./...`
Expected: exit 0.

- [ ] **Step 5: Commit**

```bash
git add cmd/controlplane/main.go internal/controlplane/server.go
git commit -m "feat(controlplane): initialize RBAC cache + authz denier at startup"
```

### Task 7.2: Add /api/v1/auth/me endpoint

**Files:**
- Create: `internal/controlplane/api/me.go`
- Create: `internal/controlplane/api/me_test.go`
- Modify: `internal/controlplane/server.go` (register route)

- [ ] **Step 1: Write the failing test**

File: `internal/controlplane/api/me_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

type fakeCache struct{ allowed map[string]map[string]struct{} }

func (f fakeCache) Can(role, perm string) bool {
	p, ok := f.allowed[role]
	if !ok {
		return false
	}
	_, ok = p[perm]
	return ok
}
func (f fakeCache) PermissionsFor(role string) []string {
	var out []string
	for p := range f.allowed[role] {
		out = append(out, p)
	}
	return out
}

func TestMe_UserReturnsRoleAndPermissions(t *testing.T) {
	cache := fakeCache{allowed: map[string]map[string]struct{}{
		"admin": {"risks.read": {}, "scans.run": {}},
	}}
	h := &MeHandler{Cache: cache}

	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "user", UserID: "u1", OrgID: "o1", Role: "admin",
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp struct {
		User        map[string]string `json:"user"`
		Permissions []string          `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.User["role"] != "admin" {
		t.Fatalf("role=%q", resp.User["role"])
	}
	if len(resp.Permissions) != 2 {
		t.Fatalf("want 2 permissions, got %v", resp.Permissions)
	}
}

func TestMe_APIKeyReturnsScopesAsPermissions(t *testing.T) {
	h := &MeHandler{Cache: fakeCache{}}
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "api_key", KeyID: "k1", OrgID: "o1",
		Scopes: []string{"findings.read", "scans.read"},
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var resp struct {
		Permissions []string `json:"permissions"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Permissions) != 2 {
		t.Fatalf("want 2, got %v", resp.Permissions)
	}
}
```

- [ ] **Step 2: Run test (fails — MeHandler not defined)**

Run: `go test ./internal/controlplane/api/ -run TestMe -v`
Expected: FAIL.

- [ ] **Step 3: Extend Cache with PermissionsFor(role)**

Modify `internal/policy/cache.go` — add:

```go
// PermissionsFor returns the sorted list of permission_ids assigned to
// the role. Used by /api/v1/auth/me.
func (c *Cache) PermissionsFor(role string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	perms := c.matrix[role]
	out := make([]string, 0, len(perms))
	for p := range perms {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
```

Add `"sort"` import.

- [ ] **Step 4: Implement MeHandler**

File: `internal/controlplane/api/me.go`:

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// PermissionResolver is the subset of policy.Cache needed by MeHandler.
type PermissionResolver interface {
	PermissionsFor(role string) []string
}

// MeHandler serves GET /api/v1/auth/me — returns the caller's identity
// and current permission set. Permissions are always computed live from
// the RBAC cache; they are NOT embedded in the JWT.
type MeHandler struct {
	Cache PermissionResolver
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHENTICATED")
		return
	}

	user := map[string]string{
		"id":     p.UserID,
		"org_id": p.OrgID,
		"role":   p.Role,
	}
	var perms []string
	switch p.Kind {
	case "user":
		perms = h.Cache.PermissionsFor(p.Role)
	case "api_key":
		perms = p.Scopes
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user":        user,
		"permissions": perms,
	})
}
```

- [ ] **Step 5: Run test (passes)**

Run: `go test ./internal/controlplane/api/ -run TestMe -v`
Expected: PASS.

- [ ] **Step 6: Register in server.go**

In `internal/controlplane/server.go` route registration block, add:

```go
meHandler := &api.MeHandler{Cache: s.rbacCache}
mux.Handle("GET /api/v1/auth/me",
    // auth middleware is already applied at the top level;
    // /me is read-only and needs no RequirePermission (every authenticated
    // user can read their own identity).
    meHandler)
```

- [ ] **Step 7: Build + manual smoke test**

Run:
```bash
go build ./...
# Start server in a separate terminal; then:
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" \
   -d '{"email":"admin@sentinel.io","password":"SentinelDemo1!"}' | jq -r .access_token)
curl -s http://localhost:8080/api/v1/auth/me -H "Authorization: Bearer $TOKEN" | jq
```
Expected: JSON with `user.role="owner"` (after migration) and a non-empty `permissions` array.

- [ ] **Step 8: Commit**

```bash
git add internal/controlplane/api/me.go internal/controlplane/api/me_test.go internal/policy/cache.go internal/controlplane/server.go
git commit -m "feat(api): add GET /api/v1/auth/me returning role + live permissions"
```

### Task 7.3: Wrap routes with RequirePermission (route-by-route)

This is an iterative task. Each sub-step migrates one logical route group.

**Files:**
- Modify: `internal/controlplane/server.go`
- Modify: the corresponding `internal/controlplane/api/*.go` files to remove inline `policy.Evaluate` calls **only after** the route is wrapped.

**Complete route → permission mapping.** Every authenticated route in `internal/controlplane/server.go` has a row. Public and self-identity routes are listed at the end. If the table omits a route that exists in code, stop and flag — do not guess.

#### Group A: risks (6 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/risks` | `risks.read` |
| `GET /api/v1/risks/{id}` | `risks.read` |
| `POST /api/v1/risks/{id}/resolve` | `risks.resolve` |
| `POST /api/v1/risks/{id}/reopen` | `risks.reopen` |
| `POST /api/v1/risks/{id}/mute` | `risks.mute` |
| `POST /api/v1/projects/{id}/risks/rebuild` | `risks.rebuild` |

#### Group B: findings (7 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/findings` | `findings.read` |
| `GET /api/v1/findings/{id}` | `findings.read` |
| `PATCH /api/v1/findings/{id}/status` | `findings.triage` |
| `POST /api/v1/findings/{id}/assign` | `findings.triage` |
| `POST /api/v1/findings/{id}/legal-hold` | `findings.legal_hold` |
| `GET /api/v1/findings/{id}/export.md` | `findings.read` |
| `GET /api/v1/findings/{id}/export.sarif` | `findings.read` |

#### Group C: scans (6 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/scans` | `scans.read` |
| `GET /api/v1/scans/{id}` | `scans.read` |
| `POST /api/v1/projects/{id}/scans` | `scans.run` |
| `POST /api/v1/scans/{id}/cancel` | `scans.cancel` |
| `GET /api/v1/scans/{id}/report.md` | `scans.read` |
| `GET /api/v1/scans/{id}/report.sarif` | `scans.read` |

#### Group D: scan targets (5 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/projects/{id}/scan-targets` | `targets.read` |
| `POST /api/v1/projects/{id}/scan-targets` | `targets.manage` |
| `GET /api/v1/scan-targets/{id}` | `targets.read` |
| `PATCH /api/v1/scan-targets/{id}` | `targets.manage` |
| `DELETE /api/v1/scan-targets/{id}` | `targets.manage` |

#### Group E: projects (4 routes)

| Route | Permission |
|---|---|
| `POST /api/v1/projects` | `projects.manage` |
| `GET /api/v1/projects` | `projects.read` |
| `GET /api/v1/projects/{id}` | `projects.read` |
| `PATCH /api/v1/projects/{id}` | `projects.manage` |

#### Group F: organizations (4 routes)

| Route | Permission |
|---|---|
| `POST /api/v1/organizations` | `organizations.manage` |
| `GET /api/v1/organizations` | `organizations.read` |
| `GET /api/v1/organizations/{id}` | `organizations.read` |
| `PATCH /api/v1/organizations/{id}` | `organizations.manage` |

#### Group G: teams (4 routes)

| Route | Permission |
|---|---|
| `POST /api/v1/organizations/{org_id}/teams` | `teams.manage` |
| `GET /api/v1/organizations/{org_id}/teams` | `teams.read` |
| `POST /api/v1/teams/{id}/members` | `teams.manage` |
| `GET /api/v1/teams/{id}/members` | `teams.read` |

#### Group H: users (2 routes — /users/me is permission-free; see end of table)

| Route | Permission |
|---|---|
| `POST /api/v1/users` | `users.manage` |
| `GET /api/v1/users` | `users.read` |

#### Group I: api_keys (3 routes)

| Route | Permission |
|---|---|
| `POST /api/v1/api-keys` | `api_keys.manage` |
| `GET /api/v1/api-keys` | `api_keys.read` |
| `DELETE /api/v1/api-keys/{id}` | `api_keys.manage` |

#### Group J: source artifacts (4 routes)

| Route | Permission |
|---|---|
| `POST /api/v1/projects/{id}/artifacts` | `artifacts.manage` |
| `GET /api/v1/projects/{id}/artifacts` | `artifacts.read` |
| `GET /api/v1/artifacts/{id}` | `artifacts.read` |
| `DELETE /api/v1/artifacts/{id}` | `artifacts.manage` |

#### Group K: auth profiles (5 routes)

| Route | Permission |
|---|---|
| `POST /api/v1/projects/{id}/auth-profiles` | `authprofiles.manage` |
| `GET /api/v1/projects/{id}/auth-profiles` | `authprofiles.read` |
| `GET /api/v1/auth-profiles/{id}` | `authprofiles.read` |
| `PATCH /api/v1/auth-profiles/{id}` | `authprofiles.manage` |
| `DELETE /api/v1/auth-profiles/{id}` | `authprofiles.manage` |

#### Group L: governance (8 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/governance/settings` | `settings.read` |
| `PUT /api/v1/governance/settings` | `settings.manage` |
| `GET /api/v1/governance/approvals` | `governance.approvals.read` |
| `GET /api/v1/governance/approvals/{id}` | `governance.approvals.read` |
| `POST /api/v1/governance/approvals/{id}/decide` | `governance.approvals.decide` |
| `POST /api/v1/governance/emergency-stop` | `governance.estop.activate` |
| `POST /api/v1/governance/emergency-stop/lift` | `governance.estop.lift` |
| `GET /api/v1/governance/emergency-stop/active` | `governance.estop.read` |

#### Group M: notifications (4 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/notifications` | `notifications.read` |
| `POST /api/v1/notifications/{id}/read` | `notifications.read` |
| `POST /api/v1/notifications/read-all` | `notifications.read` |
| `GET /api/v1/notifications/unread-count` | `notifications.read` |

> Note: notifications are per-user, and the existing handlers already filter by `user_id`. `notifications.read` is a coarse gate; the per-row ownership check stays in the handler (it is data scoping, not authorization).

#### Group N: webhooks (5 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/webhooks` | `webhooks.read` |
| `POST /api/v1/webhooks` | `webhooks.manage` |
| `PUT /api/v1/webhooks/{id}` | `webhooks.manage` |
| `DELETE /api/v1/webhooks/{id}` | `webhooks.manage` |
| `POST /api/v1/webhooks/{id}/test` | `webhooks.manage` |

#### Group O: retention (4 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/retention/policies` | `retention.read` |
| `PUT /api/v1/retention/policies` | `retention.manage` |
| `GET /api/v1/retention/records` | `retention.read` |
| `GET /api/v1/retention/stats` | `retention.read` |

#### Group P: reports (4 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/reports/findings-summary` | `reports.read` |
| `GET /api/v1/reports/triage-metrics` | `reports.read` |
| `GET /api/v1/reports/compliance-status` | `reports.read` |
| `GET /api/v1/reports/scan-activity` | `reports.read` |

#### Group Q: surface (2 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/surface` | `surface.read` |
| `GET /api/v1/surface/stats` | `surface.read` |

#### Group R: ops (2 routes)

| Route | Permission |
|---|---|
| `GET /api/v1/ops/queue` | `ops.read` |
| `GET /api/v1/ops/webhooks` | `ops.read` |

#### Group S: audit (1 route)

| Route | Permission |
|---|---|
| `GET /api/v1/audit` | `audit.read` |

#### Routes that must NOT have `RequirePermission`

| Route | Rationale |
|---|---|
| `GET /healthz` | Liveness probe. Pre-auth. |
| `GET /readyz` | Readiness probe. Pre-auth. |
| `GET /api/v1/system/health` | Public health. Pre-auth. |
| `GET /api/v1/system/version` | Public version. Pre-auth. |
| `POST /api/v1/auth/login` | Creates the session. Pre-auth by definition. |
| `POST /api/v1/auth/refresh` | Refresh token exchange. Uses its own cookie-based auth. |
| `POST /api/v1/auth/logout` | Auth'd but every role can log themselves out. |
| `GET /api/v1/users/me` | Self-identity. Every authenticated principal can read their own row. |
| `GET /api/v1/auth/me` | Added by Task 7.2 — same rationale as `/users/me`. |

These routes remain wrapped only by `AuthenticateMiddleware` (or are entirely public). No `RequirePermission` wrapping, no inline permission check.

**Total: 80 permission-gated routes across 19 groups.**

- [ ] **Step 1: Create a helper to reduce boilerplate**

Add to `internal/controlplane/server.go`:

```go
func (s *Server) authz(perm string, next http.HandlerFunc) http.Handler {
    return auth.RequirePermission(perm, s.rbacCache, s.denier)(http.HandlerFunc(next))
}
```

- [ ] **Step 2: Migrate risks routes**

In `server.go`:

```go
// Before:
// mux.HandleFunc("GET /api/v1/risks", handlers.ListRisks)
// After:
mux.Handle("GET /api/v1/risks", s.authz("risks.read", handlers.ListRisks))
mux.Handle("GET /api/v1/risks/{id}", s.authz("risks.read", handlers.GetRisk))
mux.Handle("POST /api/v1/risks/{id}/resolve", s.authz("risks.resolve", handlers.ResolveRisk))
mux.Handle("POST /api/v1/risks/{id}/mute", s.authz("risks.mute", handlers.MuteRisk))
mux.Handle("POST /api/v1/risks/{id}/reopen", s.authz("risks.reopen", handlers.ReopenRisk))
```

In `internal/controlplane/api/risks.go`, remove the `policy.Evaluate(user.Role, "...")` calls inside each handler. Leave the handler body otherwise unchanged.

- [ ] **Step 3: Run risks tests**

Run: `go test ./internal/controlplane/api/ -run Risk -v`
Expected: PASS (handlers still work; authz enforcement now at middleware).

- [ ] **Step 4: Commit**

```bash
git add internal/controlplane/server.go internal/controlplane/api/risks.go
git commit -m "refactor(api): enforce risks.* permissions at middleware"
```

- [ ] **Step 5: Scaffold the `TestAuthzMatrix` integration test BEFORE migrating further groups**

Task 10.2 contains the full authz matrix test. Scaffold it now, with rows for Groups A (risks) + B (findings) only. This gives each subsequent group a TDD gate — add rows, watch them fail, migrate, watch them pass.

Copy the scaffolding from Task 10.2 verbatim but include only Groups A + B in the `routeMatrix`. Commit:

```bash
git add internal/controlplane/api/authz_matrix_test.go internal/controlplane/api/api_test_helpers_test.go
git commit -m "test(api): scaffold authz matrix integration test (risks + findings)"
```

Run: `TEST_DATABASE_URL="$DATABASE_URL" go test ./internal/controlplane/api/ -run TestAuthzMatrix -v`
Expected: rows for risks PASS (Group A migrated). Findings rows FAIL until Group B is migrated.

- [ ] **Step 6: Migrate Group B (findings)** — same pattern as Step 2

In `server.go`:

```go
mux.Handle("GET /api/v1/findings",               s.authz("findings.read", handlers.ListFindings))
mux.Handle("GET /api/v1/findings/{id}",           s.authz("findings.read", handlers.GetFinding))
mux.Handle("PATCH /api/v1/findings/{id}/status",  s.authz("findings.triage", handlers.UpdateFindingStatus))
mux.Handle("POST /api/v1/findings/{id}/assign",   s.authz("findings.triage", handlers.AssignFinding))
mux.Handle("POST /api/v1/findings/{id}/legal-hold", s.authz("findings.legal_hold", handlers.SetLegalHold))
mux.Handle("GET /api/v1/findings/{id}/export.md",   s.authz("findings.read", handlers.ExportFindingMarkdown))
mux.Handle("GET /api/v1/findings/{id}/export.sarif", s.authz("findings.read", handlers.ExportFindingSARIF))
```

Remove inline `policy.Evaluate` calls from `internal/controlplane/api/findings.go` + `exports.go`.

Run: `TEST_DATABASE_URL="$DATABASE_URL" go test ./internal/controlplane/api/ -run TestAuthzMatrix -v`
Expected: Group A + B rows all PASS.

Commit:
```bash
git add internal/controlplane/server.go internal/controlplane/api/findings.go internal/controlplane/api/exports.go
git commit -m "refactor(api): enforce findings.* permissions at middleware"
```

- [ ] **Step 7: Migrate Group C (scans)**

In `server.go`:

```go
mux.Handle("GET /api/v1/scans",                  s.authz("scans.read", handlers.ListScans))
mux.Handle("GET /api/v1/scans/{id}",             s.authz("scans.read", handlers.GetScan))
mux.Handle("POST /api/v1/projects/{id}/scans",   s.authz("scans.run", handlers.CreateScan))
mux.Handle("POST /api/v1/scans/{id}/cancel",     s.authz("scans.cancel", handlers.CancelScan))
mux.Handle("GET /api/v1/scans/{id}/report.md",   s.authz("scans.read", handlers.ExportScanMarkdown))
mux.Handle("GET /api/v1/scans/{id}/report.sarif", s.authz("scans.read", handlers.ExportScanSARIF))
```

Add the Group C rows to `routeMatrix`. Remove `policy.Evaluate` from `internal/controlplane/api/scans.go` + `exports.go` (partial — scan-report exports live here).

Run, verify, commit with message `refactor(api): enforce scans.* permissions at middleware`.

- [ ] **Step 8: Migrate Group D (scan targets)**

```go
mux.Handle("GET /api/v1/projects/{id}/scan-targets",  s.authz("targets.read", handlers.ListScanTargets))
mux.Handle("POST /api/v1/projects/{id}/scan-targets", s.authz("targets.manage", handlers.CreateScanTarget))
mux.Handle("GET /api/v1/scan-targets/{id}",           s.authz("targets.read", handlers.GetScanTarget))
mux.Handle("PATCH /api/v1/scan-targets/{id}",         s.authz("targets.manage", handlers.UpdateScanTarget))
mux.Handle("DELETE /api/v1/scan-targets/{id}",        s.authz("targets.manage", handlers.DeleteScanTarget))
```

Remove `policy.Evaluate` from `scan_targets.go`. Commit: `refactor(api): enforce targets.* permissions at middleware`.

- [ ] **Step 9: Migrate Group E (projects)**

```go
mux.Handle("POST /api/v1/projects",           s.authz("projects.manage", handlers.CreateProject))
mux.Handle("GET /api/v1/projects",            s.authz("projects.read", handlers.ListProjects))
mux.Handle("GET /api/v1/projects/{id}",       s.authz("projects.read", handlers.GetProject))
mux.Handle("PATCH /api/v1/projects/{id}",     s.authz("projects.manage", handlers.UpdateProject))
```

Commit: `refactor(api): enforce projects.* permissions at middleware`.

- [ ] **Step 10: Migrate Group F (organizations)**

```go
mux.Handle("POST /api/v1/organizations",              s.authz("organizations.manage", handlers.CreateOrganization))
mux.Handle("GET /api/v1/organizations",               s.authz("organizations.read", handlers.ListOrganizations))
mux.Handle("GET /api/v1/organizations/{id}",          s.authz("organizations.read", handlers.GetOrganization))
mux.Handle("PATCH /api/v1/organizations/{id}",        s.authz("organizations.manage", handlers.UpdateOrganization))
```

Commit: `refactor(api): enforce organizations.* permissions at middleware`.

- [ ] **Step 11: Migrate Group G (teams)**

```go
mux.Handle("POST /api/v1/organizations/{org_id}/teams", s.authz("teams.manage", handlers.CreateTeam))
mux.Handle("GET /api/v1/organizations/{org_id}/teams",  s.authz("teams.read", handlers.ListTeams))
mux.Handle("POST /api/v1/teams/{id}/members",           s.authz("teams.manage", handlers.AddTeamMember))
mux.Handle("GET /api/v1/teams/{id}/members",            s.authz("teams.read", handlers.ListTeamMembers))
```

Commit: `refactor(api): enforce teams.* permissions at middleware`.

- [ ] **Step 12: Migrate Group H (users) — NOT /users/me**

```go
mux.Handle("POST /api/v1/users", s.authz("users.manage", handlers.CreateUser))
mux.Handle("GET /api/v1/users",  s.authz("users.read",   handlers.ListUsers))
// GET /api/v1/users/me stays as-is (no RequirePermission)
```

Commit: `refactor(api): enforce users.* permissions at middleware`.

- [ ] **Step 13: Migrate Group I (api_keys)**

```go
mux.Handle("POST /api/v1/api-keys",         s.authz("api_keys.manage", handlers.CreateAPIKey))
mux.Handle("GET /api/v1/api-keys",          s.authz("api_keys.read",   handlers.ListAPIKeys))
mux.Handle("DELETE /api/v1/api-keys/{id}",  s.authz("api_keys.manage", handlers.RevokeAPIKey))
```

Commit: `refactor(api): enforce api_keys.* permissions at middleware`.

- [ ] **Step 14: Migrate Group J (artifacts)**

```go
mux.Handle("POST /api/v1/projects/{id}/artifacts", s.authz("artifacts.manage", handlers.CreateSourceArtifact))
mux.Handle("GET /api/v1/projects/{id}/artifacts",  s.authz("artifacts.read",   handlers.ListSourceArtifacts))
mux.Handle("GET /api/v1/artifacts/{id}",           s.authz("artifacts.read",   handlers.GetSourceArtifact))
mux.Handle("DELETE /api/v1/artifacts/{id}",        s.authz("artifacts.manage", handlers.DeleteSourceArtifact))
```

Commit: `refactor(api): enforce artifacts.* permissions at middleware`.

- [ ] **Step 15: Migrate Group K (auth profiles)**

```go
mux.Handle("POST /api/v1/projects/{id}/auth-profiles", s.authz("authprofiles.manage", handlers.CreateAuthProfile))
mux.Handle("GET /api/v1/projects/{id}/auth-profiles",  s.authz("authprofiles.read",   handlers.ListAuthProfiles))
mux.Handle("GET /api/v1/auth-profiles/{id}",           s.authz("authprofiles.read",   handlers.GetAuthProfile))
mux.Handle("PATCH /api/v1/auth-profiles/{id}",         s.authz("authprofiles.manage", handlers.UpdateAuthProfile))
mux.Handle("DELETE /api/v1/auth-profiles/{id}",        s.authz("authprofiles.manage", handlers.DeleteAuthProfile))
```

Commit: `refactor(api): enforce authprofiles.* permissions at middleware`.

- [ ] **Step 16: Migrate Group L (governance)**

```go
mux.Handle("GET /api/v1/governance/settings",                s.authz("settings.read",                handlers.GetGovernanceSettings))
mux.Handle("PUT /api/v1/governance/settings",                s.authz("settings.manage",              handlers.UpdateGovernanceSettings))
mux.Handle("GET /api/v1/governance/approvals",               s.authz("governance.approvals.read",    handlers.ListApprovals))
mux.Handle("GET /api/v1/governance/approvals/{id}",          s.authz("governance.approvals.read",    handlers.GetApproval))
mux.Handle("POST /api/v1/governance/approvals/{id}/decide",  s.authz("governance.approvals.decide",  handlers.DecideApproval))
mux.Handle("POST /api/v1/governance/emergency-stop",         s.authz("governance.estop.activate",    handlers.ActivateEmergencyStop))
mux.Handle("POST /api/v1/governance/emergency-stop/lift",    s.authz("governance.estop.lift",        handlers.LiftEmergencyStop))
mux.Handle("GET /api/v1/governance/emergency-stop/active",   s.authz("governance.estop.read",        handlers.ListActiveEmergencyStops))
```

Commit: `refactor(api): enforce governance.* + settings.* permissions at middleware`.

- [ ] **Step 17: Migrate Group M (notifications)**

```go
mux.Handle("GET /api/v1/notifications",                s.authz("notifications.read", handlers.ListNotificationsHandler))
mux.Handle("POST /api/v1/notifications/{id}/read",     s.authz("notifications.read", handlers.MarkNotificationRead))
mux.Handle("POST /api/v1/notifications/read-all",      s.authz("notifications.read", handlers.MarkAllNotificationsRead))
mux.Handle("GET /api/v1/notifications/unread-count",   s.authz("notifications.read", handlers.GetUnreadCount))
```

Commit: `refactor(api): enforce notifications.read permission at middleware`.

- [ ] **Step 18: Migrate Group N (webhooks)**

```go
mux.Handle("GET /api/v1/webhooks",             s.authz("webhooks.read",   handlers.ListWebhooks))
mux.Handle("POST /api/v1/webhooks",            s.authz("webhooks.manage", handlers.CreateWebhook))
mux.Handle("PUT /api/v1/webhooks/{id}",        s.authz("webhooks.manage", handlers.UpdateWebhook))
mux.Handle("DELETE /api/v1/webhooks/{id}",     s.authz("webhooks.manage", handlers.DeleteWebhook))
mux.Handle("POST /api/v1/webhooks/{id}/test",  s.authz("webhooks.manage", handlers.TestWebhook))
```

Commit: `refactor(api): enforce webhooks.* permissions at middleware`.

- [ ] **Step 19: Migrate Group O (retention)**

```go
mux.Handle("GET /api/v1/retention/policies",  s.authz("retention.read",   handlers.GetRetentionPolicies))
mux.Handle("PUT /api/v1/retention/policies",  s.authz("retention.manage", handlers.UpdateRetentionPolicies))
mux.Handle("GET /api/v1/retention/records",   s.authz("retention.read",   handlers.ListRetentionRecords))
mux.Handle("GET /api/v1/retention/stats",     s.authz("retention.read",   handlers.GetRetentionStats))
```

Commit: `refactor(api): enforce retention.* permissions at middleware`.

- [ ] **Step 20: Migrate Group P (reports)**

```go
mux.Handle("GET /api/v1/reports/findings-summary",   s.authz("reports.read", handlers.FindingsSummary))
mux.Handle("GET /api/v1/reports/triage-metrics",     s.authz("reports.read", handlers.TriageMetrics))
mux.Handle("GET /api/v1/reports/compliance-status",  s.authz("reports.read", handlers.ComplianceStatus))
mux.Handle("GET /api/v1/reports/scan-activity",      s.authz("reports.read", handlers.ScanActivity))
```

Commit: `refactor(api): enforce reports.read permission at middleware`.

- [ ] **Step 21: Migrate Group Q (surface)**

```go
mux.Handle("GET /api/v1/surface",        s.authz("surface.read", handlers.ListSurfaceEntries))
mux.Handle("GET /api/v1/surface/stats",  s.authz("surface.read", handlers.GetSurfaceStats))
```

Commit: `refactor(api): enforce surface.read permission at middleware`.

- [ ] **Step 22: Migrate Group R (ops)**

```go
mux.Handle("GET /api/v1/ops/queue",     s.authz("ops.read", handlers.GetQueueStatus))
mux.Handle("GET /api/v1/ops/webhooks",  s.authz("ops.read", handlers.GetWebhookStatus))
```

Commit: `refactor(api): enforce ops.read permission at middleware`.

- [ ] **Step 23: Migrate Group S (audit)**

```go
mux.Handle("GET /api/v1/audit",  s.authz("audit.read", handlers.ListAuditEvents))
```

Commit: `refactor(api): enforce audit.read permission at middleware`.

- [ ] **Step 24: Final sweep**

After every group is migrated, run:

```bash
# Every protected route should now use s.authz in server.go; the grep should show no bare mux.HandleFunc
# for any /api/v1/ route except the 9 exempt ones listed above.
grep -n 'mux\.HandleFunc("[A-Z]\+ /api/v1/' internal/controlplane/server.go

# Every inline policy.Evaluate should be gone from handlers.
grep -rn 'policy\.Evaluate' internal/controlplane/api/ | grep -v '_test.go'

# Full authz matrix must pass.
TEST_DATABASE_URL="$DATABASE_URL" go test ./internal/controlplane/api/ -run TestAuthzMatrix -v
```

Expected:
- The first grep shows exactly 9 matches (the permission-free routes listed earlier).
- The second grep shows zero matches.
- The authz matrix test passes for every route × every role.

Commit the matrix fully populated:

```bash
git add internal/controlplane/api/authz_matrix_test.go
git commit -m "test(api): complete authz matrix for all 80 permission-gated routes"
```

- [ ] **Step 25: CI guard against re-introduction**

Create `scripts/check-policy-evaluate.sh`:

```bash
#!/usr/bin/env bash
# Fails if any call to policy.Evaluate remains in api handlers.
# Intentionally allowed: internal/policy/*.go (the shim itself), tests.
set -eu
matches=$(grep -rn "policy\.Evaluate" internal/controlplane/api/ || true)
if [ -n "$matches" ]; then
    echo "ERROR: policy.Evaluate still called outside middleware:" >&2
    echo "$matches" >&2
    exit 1
fi
echo "OK: no inline policy.Evaluate calls in handlers."
```

Make executable: `chmod +x scripts/check-policy-evaluate.sh`.

Add to CI pipeline (for this project, append to the existing Makefile `check` target or similar).

- [ ] **Step 26: Commit the guard**

```bash
git add scripts/check-policy-evaluate.sh
git commit -m "ci: guard against re-introduction of inline policy.Evaluate"
```

---

## Chunk 8: pg_notify Reload Wiring

### Task 8.1: Listener goroutine

**Files:**
- Modify: `internal/policy/cache.go`

- [ ] **Step 1: Add Listen method**

Append to `internal/policy/cache.go`:

```go
// Listen starts a goroutine that LISTENs on the given channel and calls
// Reload whenever a NOTIFY arrives. Also runs a 60s safety poll to catch
// any missed NOTIFY (network blip, deploy race). Cancel ctx to stop.
//
// Channel convention: "role_permissions_changed".
func (c *Cache) Listen(ctx context.Context, pool *pgxpool.Pool, channel string, logger *slog.Logger) {
	go func() {
		reconnectDelay := time.Second
		for ctx.Err() == nil {
			if err := c.listenOnce(ctx, pool, channel, logger); err != nil {
				logger.Warn("rbac cache listener lost, reconnecting",
					"err", err, "delay", reconnectDelay)
				select {
				case <-ctx.Done():
					return
				case <-time.After(reconnectDelay):
				}
				if reconnectDelay < 30*time.Second {
					reconnectDelay *= 2
				}
				continue
			}
			reconnectDelay = time.Second
		}
	}()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.Reload(ctx, pool); err != nil {
					logger.Warn("rbac cache safety reload failed", "err", err)
				}
			}
		}
	}()
}

func (c *Cache) listenOnce(ctx context.Context, pool *pgxpool.Pool, channel string, logger *slog.Logger) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return err
	}
	logger.Info("rbac cache listener started", "channel", channel)

	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		logger.Debug("rbac cache notify received", "channel", n.Channel, "payload", n.Payload)
		if err := c.Reload(ctx, pool); err != nil {
			logger.Warn("rbac cache reload on notify failed", "err", err)
		}
	}
}
```

Add imports: `"log/slog"`, `"time"`, `"github.com/jackc/pgx/v5"`.

- [ ] **Step 2: Call from main**

In `cmd/controlplane/main.go`, after `cache.Reload(...)`:

```go
cache.Listen(ctx, pool, "role_permissions_changed", logger)
```

- [ ] **Step 3: Trigger NOTIFY from admin endpoints (deferred)**

No admin endpoint mutates role_permissions in Phase 1 — the seed is immutable. The listener is forward-compatible with future custom-role endpoints. For now the 60s safety reload is enough.

- [ ] **Step 4: Manual verification**

Run the server, then in psql:

```sql
NOTIFY role_permissions_changed, 'manual-test';
```

Expected: log line "rbac cache notify received".

- [ ] **Step 5: Commit**

```bash
git add internal/policy/cache.go cmd/controlplane/main.go
git commit -m "feat(policy): subscribe RBAC cache to pg_notify role_permissions_changed"
```

---

## Chunk 9: Frontend Permission Hook + Gating

### Task 9.1: useAuth + use-permissions hook

**Files:**
- Modify: `web/features/auth/hooks.ts`
- Create: `web/features/auth/use-permissions.ts`

- [ ] **Step 1: Read current hooks.ts**

Run: `sed -n '1,80p' web/features/auth/hooks.ts`

- [ ] **Step 2: Add fetch for /auth/me in auth provider or useAuth**

Create `web/features/auth/use-permissions.ts`:

```ts
"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api-client";

export interface Me {
  user: { id: string; org_id: string; role: string };
  permissions: string[];
}

export function useMe() {
  return useQuery<Me>({
    queryKey: ["auth", "me"],
    queryFn: () => api.get<Me>("/api/v1/auth/me"),
    staleTime: 5 * 60 * 1000, // 5 minutes — matches spec
    refetchOnWindowFocus: true,
  });
}

export function usePermissions(): {
  can: (perm: string) => boolean;
  isLoading: boolean;
} {
  const { data, isLoading } = useMe();
  const perms = new Set(data?.permissions ?? []);
  return {
    can: (perm: string) => perms.has(perm),
    isLoading,
  };
}
```

- [ ] **Step 3: Create `<Can>` component**

File: `web/components/security/can.tsx`:

```tsx
"use client";

import { usePermissions } from "@/features/auth/use-permissions";

export function Can({
  permission,
  children,
  fallback = null,
}: {
  permission: string;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}) {
  const { can, isLoading } = usePermissions();
  if (isLoading) return null;
  return can(permission) ? <>{children}</> : <>{fallback}</>;
}
```

- [ ] **Step 4: Gate sidebar + key buttons**

Modify `web/components/layout/sidebar.tsx` to wrap nav items with `<Can>` per their required permission (e.g., Settings → `settings.read`, Audit Log → `audit.read`, Users — if surfaced — `users.read`).

Example for Audit Log:

```tsx
<Can permission="audit.read">
  <Link href="/audit" ...>Audit Log</Link>
</Can>
```

- [ ] **Step 5: Smoke test in browser**

Run the full stack. Log in as a `developer` user (create one if needed: `INSERT INTO core.users ... role='developer'`). Confirm the sidebar hides Audit Log / Settings / Users.

- [ ] **Step 6: Commit**

```bash
git add web/features/auth/use-permissions.ts web/components/security/can.tsx web/components/layout/sidebar.tsx
git commit -m "feat(web): add useMe/usePermissions + <Can> UI gating"
```

---

## Chunk 10: Legacy Cleanup + Integration Test

### Task 10.1: Retire policy.Evaluate shim

**Files:**
- Modify: `internal/policy/rbac.go`

- [ ] **Step 1: Verify no call sites remain**

Run: `grep -rn "policy\.Evaluate" --include="*.go" . | grep -v _test.go | grep -v internal/policy/`
Expected: empty output.

- [ ] **Step 2: Delete rbac.go's matrix and Evaluate**

Replace the file's body with:

```go
// Package policy previously held the hardcoded RBAC matrix and the
// Evaluate() function. Both are retired in favour of the DB-driven
// cache (cache.go) + RequirePermission middleware. This file is kept
// as the package home for future policy helpers.
package policy
```

- [ ] **Step 3: Build + test**

Run: `go build ./... && go test ./... -short`
Expected: all PASS.

- [ ] **Step 4: Run the guard script**

Run: `./scripts/check-policy-evaluate.sh`
Expected: "OK: no inline policy.Evaluate calls."

- [ ] **Step 5: Commit**

```bash
git add internal/policy/rbac.go
git commit -m "refactor(policy): remove legacy Evaluate + hardcoded matrix"
```

### Task 10.2: End-to-end authz matrix test

**Files:**
- Create: `internal/controlplane/api/authz_matrix_test.go`

- [ ] **Step 1: Write the test**

File: `internal/controlplane/api/authz_matrix_test.go`:

```go
package api_test

// This test hits every authenticated route with a token for each of the
// 5 roles and asserts the expected 200/403 outcome. It uses a real
// controlplane server bound to an ephemeral port and the TEST_DATABASE_URL
// database (migrated + seeded).
//
// The test is the safety net against a handler that accidentally loses
// its RequirePermission wrapper.

import (
	"net/http"
	"testing"
	// imports elided for brevity — see existing api tests for patterns
)

type routeCase struct {
	Method  string
	Path    string
	RoleExpected map[string]int // role → expected HTTP status
}

var routeMatrix = []routeCase{
	{"GET", "/api/v1/risks", map[string]int{
		"owner": 200, "admin": 200, "security_engineer": 200,
		"auditor": 200, "developer": 200,
	}},
	{"POST", "/api/v1/risks/00000000-0000-0000-0000-000000000001/resolve", map[string]int{
		"owner": 200, "admin": 200, "security_engineer": 200,
		"auditor": 403, "developer": 403,
	}},
	{"POST", "/api/v1/scans", map[string]int{
		"owner": 200, "admin": 200, "security_engineer": 200,
		"auditor": 403, "developer": 403,
	}},
	{"POST", "/api/v1/users", map[string]int{
		"owner": 200, "admin": 403, "security_engineer": 403,
		"auditor": 403, "developer": 403,
	}},
	{"GET", "/api/v1/audit", map[string]int{
		"owner": 200, "admin": 200, "security_engineer": 200,
		"auditor": 200, "developer": 403,
	}},
	// ... add one row per route-permission pair. Tests can reuse this slice
	// in a table-driven loop to keep the code ~50 lines.
}

func TestAuthzMatrix(t *testing.T) {
	srv := startTestServer(t) // helper that brings up an in-process server
	defer srv.Close()

	tokens := map[string]string{
		"owner":             srv.IssueTokenForRole(t, "owner"),
		"admin":             srv.IssueTokenForRole(t, "admin"),
		"security_engineer": srv.IssueTokenForRole(t, "security_engineer"),
		"auditor":           srv.IssueTokenForRole(t, "auditor"),
		"developer":         srv.IssueTokenForRole(t, "developer"),
	}

	for _, rc := range routeMatrix {
		for role, wantStatus := range rc.RoleExpected {
			t.Run(rc.Method+" "+rc.Path+" as "+role, func(t *testing.T) {
				req, _ := http.NewRequest(rc.Method, srv.URL+rc.Path, nil)
				req.Header.Set("Authorization", "Bearer "+tokens[role])
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				// We accept any 2xx as "allowed" (the request may 404 on a
				// missing id), and 403 as "denied".
				if wantStatus == 200 && resp.StatusCode >= 400 && resp.StatusCode != 404 {
					t.Errorf("role=%s got %d want allow (2xx or 404)", role, resp.StatusCode)
				}
				if wantStatus == 403 && resp.StatusCode != 403 {
					t.Errorf("role=%s got %d want 403", role, resp.StatusCode)
				}
			})
		}
	}
}
```

(The `startTestServer` + `IssueTokenForRole` helpers should be added to a new `api_test_helpers_test.go` — see the existing scans tests for the pattern.)

- [ ] **Step 2: Run the test**

Run: `TEST_DATABASE_URL="$DATABASE_URL" go test ./internal/controlplane/api/ -run TestAuthzMatrix -v`
Expected: PASS for every route × role pair.

- [ ] **Step 3: Commit**

```bash
git add internal/controlplane/api/authz_matrix_test.go internal/controlplane/api/api_test_helpers_test.go
git commit -m "test(api): full authz matrix — every route × every role"
```

### Task 10.3: Remove compatMode translator (scheduled +14 days after Phase 1 deploy)

**Do not execute until 14 days after Phase 1 production deploy.** Add a dated TODO in `pkg/auth/jwt.go` (Step 1 below) at the time of deploy so the removal is not forgotten.

**Files:**
- Modify: `pkg/auth/jwt.go`
- Modify: `pkg/auth/jwt_test.go`

- [ ] **Step 1: On Phase 1 deploy day, add a dated TODO to jwt.go**

Insert comment above `compatRoleMap`:

```go
// TODO(compat-removal): remove this map + translateLegacyRole call on or
// after YYYY-MM-DD (deploy_date + 14 days). By that point all in-flight
// access tokens (15m TTL) and refresh tokens (7d TTL, re-issues with new
// role strings after rename migration) will have rotated.
```

Commit: `chore(auth): schedule compatMode removal YYYY-MM-DD`.

- [ ] **Step 2: On T+14, verify no tokens with old role strings are still in circulation**

In Redis:
```bash
# No active JTIs older than 14 days should exist (refresh token TTL is 7d).
redis-cli --scan --pattern 'session:*' | wc -l
```

Sample a few session records for their associated user's role in DB:
```bash
# Pick a few JTIs and confirm their user has a new-vocabulary role.
for jti in $(redis-cli --scan --pattern 'session:*' | head -5); do
    user_id=$(redis-cli GET "$jti")
    psql "$DATABASE_URL" -tAc "SELECT role FROM core.users WHERE id='$user_id';"
done
```

Expected: every returned role is one of `owner`, `admin`, `security_engineer`, `auditor`, `developer`. No `platform_admin`, no `security_admin`, no `appsec_analyst`.

- [ ] **Step 3: Delete the translator**

Remove from `pkg/auth/jwt.go`:
- the `compatRoleMap` variable
- the `translateLegacyRole` function
- the `claims.Role = translateLegacyRole(claims.Role)` line in `ValidateToken`

- [ ] **Step 4: Delete the translator test**

Remove `TestValidateToken_CompatModeTranslatesOldRoles` from `pkg/auth/jwt_test.go`.

- [ ] **Step 5: Build + run**

Run: `go build ./... && go test ./pkg/auth/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/auth/jwt.go pkg/auth/jwt_test.go
git commit -m "chore(auth): remove compatMode role translator (14-day window expired)"
```

---

## Verification Checklist

Before declaring Phase 1 shippable:

### Build / test gates

- [ ] All migrations (024 + 025) applied cleanly on a fresh DB — `SELECT count(*) FROM auth.permissions` returns 41, `auth.role_permissions` returns 137
- [ ] All migrations rolled back cleanly on a fresh DB (with no developer users) and then re-applied — down migrations leave no orphaned constraints
- [ ] `./scripts/check-policy-evaluate.sh` passes — zero inline `policy.Evaluate` in `internal/controlplane/api/`
- [ ] `grep 'mux\.HandleFunc("[A-Z]\+ /api/v1/' internal/controlplane/server.go` returns exactly 9 matches (the permission-free routes)
- [ ] `go test ./... -race` passes
- [ ] `TEST_DATABASE_URL=... go test ./internal/controlplane/api/ -run TestAuthzMatrix` passes for every (route × role) pair across all 19 groups

### Runtime verification

- [ ] Manual: start fresh server, inspect logs for "rbac cache listener started" + "rbac cache init" at startup
- [ ] Manual: `NOTIFY role_permissions_changed` in psql, confirm log line shows the cache reloaded within ~10ms
- [ ] Manual: mutate a row in `auth.role_permissions` (test environment only) and confirm `Can()` reflects the change after NOTIFY fires — end-to-end live-reload verification
- [ ] Manual: login as each of the 5 roles, confirm sidebar gating matches the permission matrix (Owner sees everything, Developer sees only Risks + Findings + Scans + Projects + Notifications)
- [ ] Manual: issue a JWT with old role string (`platform_admin`) via a script, confirm `/api/v1/auth/me` returns `role="owner"` with Owner's permission list
- [ ] Manual: call `/api/v1/auth/me` with a valid API key (not JWT) — confirm `role=""` and `permissions` equals the key's `scopes` array exactly
- [ ] Manual: call a permission-gated route (e.g. `POST /api/v1/scans`) with an API key whose scopes include `scans.run` — confirm 2xx
- [ ] Manual: call the same route with an API key whose scopes exclude `scans.run` — confirm 403 with `code=INSUFFICIENT_SCOPE` and an `authz.denied` audit event recorded

### Frontend verification

- [ ] Manual: as `developer`, verify sidebar hides Audit Log, Settings, API Keys, Users — but shows Risks, Findings, Scans, Projects, Notifications
- [ ] Manual: as `auditor`, verify every page loads but no action buttons (Resolve, Run Scan, Invite User, etc.) render
- [ ] Manual: tamper the client-side permission cache in devtools to show a forbidden button, click it, confirm the server returns 403 (UI gate is advisory, server is authoritative)

### Post-deploy scheduling

- [ ] On deploy day, Task 10.3 Step 1 executed: dated TODO added to `pkg/auth/jwt.go`
- [ ] Calendar reminder or tracking issue created for `deploy_date + 14 days` to execute Task 10.3 Steps 2-6

## Notes on Execution

- **Each task is a commit.** Don't batch. Small commits make the route migration (Chunk 7) reviewable one route group at a time.
- **Task 7.5** is the biggest risk: ~20 handlers × 2 edits each. Work one route group per PR, not all at once. Run `TestAuthzMatrix` after every group.
- **The compatMode window** starts the day Phase 1 ships. Set a calendar reminder for +14 days to remove the `compatRoleMap` + the `translateLegacyRole` call. That's a 1-line PR.
