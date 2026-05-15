# Phase 2 Execution Notes

This branch (`feature/iac-phase2-api-keys`, stacked on `feature/iac-phase1-rbac`)
executes the Phase 2 API key scopes plan against the `main` tree as of
2026-04. Several tasks touch code that lives on `phase2/api-dast` (retention
worker, web frontend, governance package) but not on `main`. Those tasks are
deferred; this doc records what was built here and what remains.

## Shipped in this PR

| Chunk | Tasks | What it shipped |
|---|---|---|
| 1 | 1.1, 1.2, 1.3 | Migrations 026 (api_keys columns), 027 (proposed_scopes), 028 (role-downgrade trigger + pending_audit_events) |
| 2 | 2.1, 2.2, 2.3 | `pkg/apikeys/scope_validation.go` + typed errors; `CreateInput` struct + creator-ceiling enforcement; `POST /api/v1/api-keys` handler |
| 3 | 3.1, 3.2 | Atomic `Rotate` function; `POST /api/v1/api-keys/{id}/rotate` handler |
| 5 | 5.1 | `SessionStore.RevokeAllForUser`; `LISTEN user_sessions_revoke` goroutine wired from controlplane |
| prep | — | Imported `migrations/022_api_keys.up/down.sql` + `pkg/apikeys/apikeys.go` from `phase2/api-dast` (the api_keys foundation the plan builds on) |

## Deferred — needs `phase2/api-dast` merge first

### Chunk 4 — Expiration sweep + pending-audit drain (Tasks 4.1, 4.2)

**Why deferred:** `cmd/retention-worker/` does not exist on `main`. Both tasks
add goroutines to that binary (`sweepExpiredAPIKeys` hourly; `drainPendingAudit
Events` every 30s). Without the retention worker scaffolding on `main`, there
is no place to wire them.

**Mitigations during the gap:**
- The Resolve middleware already rejects expired keys at request time (the
  `expires_at < now()` predicate), so key expiration is enforced even without
  the sweep. The sweep is cosmetic cleanup + audit.
- `pending_audit_events` rows written by the role-downgrade trigger (Task 1.3)
  are NOT drained until a worker picks them up. In the meantime:
  - The primary security effect (Redis JTI invalidation) happens instantly via
    the session-revoke listener (Task 5.1).
  - The audit events accumulate in the side table; there is no data loss, only
    delivery delay until a drainer lands.

**Follow-up ticket:** implement Chunk 4 once retention-worker lands on `main`,
OR wire the two goroutines directly into the controlplane startup as an
interim (matches how Phase 1's cache listener is wired).

### Chunk 6 — Backfill CLI (Task 6.1) + JTI index backfill

**Why deferred:**
- `cmd/migrate-api-keys/` — new CLI, additive but large; not required for any
  happy-path flow. Production keys created after this deploy get explicit
  scopes from day one.
- `cmd/backfill-jti-index/` — one-shot Redis scan that populates
  `user:<userID>:sessions` sets from pre-existing `session:<jti>` keys. The
  sets are only needed by `RevokeAllForUser`, which is only called from the
  pg_notify listener, which is only triggered by a role downgrade on a user
  whose keys exceed the new role's scopes. Narrow failure window.

**Required operational step before enabling role-downgrade revocation in
production:**

1. Deploy this PR's binary.
2. Apply migrations 026/027/028.
3. **Run the JTI backfill** (provided as ad-hoc Go script in the follow-up,
   or a one-liner below in the meantime):
   ```go
   // scan session:* keys, GET userID, SADD user:<userID>:sessions <jti>
   ```
4. Only then is it safe for admins to change user roles.

If step 3 is skipped, sessions created before the deploy will NOT be revoked
on role downgrade until their access tokens expire (15m) + refresh tokens
(7d). Acceptable for small tenants, unacceptable for high-security customers.

**Follow-up ticket:** package the JTI backfill as `cmd/backfill-jti-index/`
so operators can run it declaratively.

### Chunk 7 — Frontend (Tasks 7.1–7.4)

**Why deferred:** `web/` does not exist on `main`. The Next.js frontend lives
on `phase2/api-dast`. Once merged, these tasks add:
- `web/lib/api.ts` apikeys client methods
- `web/lib/hooks.ts` `useAPIKeys` + `useCreateAPIKey`
- Scope picker component
- Create-key dialog + one-time plaintext modal
- API-keys table/page

All purely UI — the backend contract is already in place (`/api/v1/api-keys`
CRUD + rotate, `CreateResult` with `json:"plaintext"`).

## What operators need to know for production

1. **Before applying migration 028**, verify no existing user has a role for
   which the `(scopes - new_role_permissions)` set would be large. The
   trigger revokes any user-owned key where even ONE scope exceeds the new
   role. This is intentional.
2. **Before enabling role changes**, run the JTI backfill (see Chunk 6 above).
3. **After deploy**, monitor `auth.pending_audit_events` — rows should be
   draining (once Chunk 4 ships) or accumulating with a follow-up scheduled.
