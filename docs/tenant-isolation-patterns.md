# Tenant Isolation Patterns

Code-level rules for multi-tenant safety in SentinelCore. The Phase 7
plan §4 establishes five defensive layers; this document is the
day-to-day reference for writing handlers, services, and migrations
that respect them.

Enforced automatically where possible:
- `pkg/tenant/lint_test.go` fails CI on direct `pool.Exec`/`pool.Query`
  outside the allowlist.
- `docs/secret-path-catalog.md` drift check enforces the secret path
  taxonomy.

---

## 1. The golden path

Every handler that touches tenant data follows this template:

```go
func (h *Handlers) DoTheThing(w http.ResponseWriter, r *http.Request) {
    user := requireAuth(w, r)
    if user == nil {
        return
    }

    // (Optional) fail-fast ownership check before touching the DB.
    if err := tenant.ValidateProjectBelongsTo(r.Context(), h.pool,
        r.PathValue("project_id"), user.OrgID); tenant.IsNotVisible(err) {
        writeError(w, http.StatusNotFound, "not found", "NOT_FOUND")
        return
    }

    err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
        func(ctx context.Context, tx pgx.Tx) error {
            // Every query inside this closure runs with
            //   app.current_org_id = user.OrgID
            //   app.current_user_id = user.UserID
            // set via set_config('...', $1, true). RLS kicks in.
            _, err := tx.Exec(ctx, `UPDATE core.projects SET ...`, ...)
            return err
        })
    if err != nil {
        // ... handle ...
    }
}
```

Three things to notice:

1. **Pool goes in, transaction comes out.** Handlers never call
   `h.pool.Query`/`Exec` directly — only `tenant.TxUser`.
2. **Org + User scope set explicitly.** The first argument to
   `TxUser` is `orgID`, second is `userID` — the order is chosen so
   that passing them backwards is likely to surface as a failing test.
3. **Tenancy check is separate from the operation.** `Validate*`
   functions return `tenant.ErrNotVisible` for both "doesn't exist"
   and "exists in another org" — handlers map both to 404.

---

## 2. Anti-footguns

### 2.1 Never pass `*pgxpool.Pool` into business logic

Handlers get `h.pool`; they call `tenant.TxUser` with it. Business
logic functions that need a DB ("fetch findings for this risk")
should take `pgx.Tx` as a parameter so they run within the caller's
transaction:

```go
// BAD — breaks the RLS contract by opening its own connection
func loadFindings(ctx context.Context, pool *pgxpool.Pool, riskID string) (...) {
    rows, _ := pool.Query(ctx, `SELECT ... WHERE cluster_id = $1`, riskID)
    ...
}

// GOOD — participates in the parent transaction, inherits GUCs
func loadFindings(ctx context.Context, tx pgx.Tx, riskID string) (...) {
    rows, _ := tx.Query(ctx, `SELECT ... WHERE cluster_id = $1`, riskID)
    ...
}
```

See `internal/controlplane/api/risks.go` for concrete examples
(`loadEvidence`, `loadClusterFindings`, `loadClusterRelations`).

### 2.2 Never trust `{id}` from the URL without validating tenancy

A signed JWT tells you WHO the caller is, not WHAT they're allowed
to touch. Use `tenant.ValidateProjectBelongsTo` / `ValidateFindingBelongsTo`
for the high-risk cases:

```go
if err := tenant.ValidateProjectBelongsTo(ctx, h.pool, id, user.OrgID);
    tenant.IsNotVisible(err) {
    return 404
}
```

For everything else, the `tenant.TxUser` wrapper + RLS + `WHERE org_id = $N`
predicate combine to catch cross-tenant access at the DB boundary.

### 2.3 Never distinguish "forbidden" from "not found"

Returning 403 for someone else's resource and 404 for a genuinely
missing one leaks the existence of the resource — a classic
timing/enumeration attack. SentinelCore's convention:

| Situation | HTTP |
|---|---|
| Resource exists and caller can read it | 200 |
| Resource exists but belongs to another tenant | **404** |
| Resource does not exist | **404** |
| Caller is not authenticated | 401 |
| Caller is authenticated but lacks the RBAC capability | 403 |

403 is reserved for RBAC mismatches on resources in the caller's
OWN tenant (e.g. a developer trying to delete a finding they can
see but don't own).

### 2.4 Never log org_id in an error returned to the user

Internal logs: log everything including IDs. User-facing errors:
generic. `writeError(w, 404, "project not found", "NOT_FOUND")` —
not `"project <uuid> belongs to org <uuid>"`.

### 2.5 Never do a bulk UPDATE without `WHERE org_id = $1`

Even with RLS enforcing org isolation, the explicit predicate is
the primary proof for code reviewers that this statement respects
the boundary. `UPDATE findings.findings SET foo = 'bar'` without a
filter is a red flag regardless of what the RLS policy says.

Platform-admin cross-tenant operations (audit export, global
reporting) route through `tenant.TxGlobal` which sets the explicit
`app.audit_global_read=true` escape hatch. Every call site of
`TxGlobal` is on the security review checklist.

### 2.6 Never set `app.audit_global_read=true` at pool level

It's a transaction-local GUC for a reason. A leaked session-level
setting is a cross-tenant data spill with no audit trail. The
`tenant.TxGlobal` helper sets it with `is_local=true` so commit
erases the binding.

### 2.7 Never keep parallel `key_verifier` + `key_hash` columns forever

The API key transition has a hard 90-day window (per the Phase 7
plan). After it, drop the legacy `key_hash` column — leaving both
columns around invites "we'll fix it later" bugs that never get
fixed.

### 2.8 Never trust `r.RemoteAddr` for audit actor_ip

Behind nginx, `r.RemoteAddr` is the LB, not the user. Phase 6's
`audit.normaliseIP` unpacks X-Forwarded-For; use it rather than
writing your own parser. Rewriting the parser is how regressions
start.

### 2.9 Never `pg_dump` ad-hoc for transfers

Use `sc-backup` — the age-encrypted output is the only sanctioned
transport. Ad-hoc dumps leak tenant data to disk unencrypted.

### 2.10 Never `json.Marshal` a struct containing `tenant.Scope`

The Scope type is designed to be passed down the call stack, not
serialized. A future change can add a `MarshalJSON` that panics on
zero-value; for now, keep it out of JSON bodies by convention.

---

## 3. The five defensive layers

For context on WHY the rules above exist:

| # | Layer | Enforced by | Failure mode |
|---|---|---|---|
| 1 | RBAC | `internal/policy` capability checks at the route | Caller has auth, lacks capability — 403 |
| 2 | RLS | Postgres policies on every tenant schema | Caller reaches a table without `app.current_org_id` set — 0 rows returned |
| 3 | Explicit org_id predicate | `WHERE org_id = $1` in every tenant-scoped query | Code review red flag |
| 4 | Envelope / append-only / BYPASSRLS roles | Migrations 037/040 triggers + role grants | DB-level refusal (`42501` / custom trigger error) |
| 5 | Cross-tenant test matrix | `TestCrossTenantLeakageMatrix` with seeded tenants | CI fails when a new handler leaks |

Rule of thumb: layer 1 is the fastest, layer 5 is the most thorough.
An attack that slips past one layer should be caught by the next.
When you add a handler, check you've covered 1–3 at code-write time;
4 is automatic if your queries go through `tenant.Tx`; 5 catches the
regressions.

---

## 4. Quick reference: migrating off legacy patterns

If you're touching a handler that still uses the old patterns, here's
the transformation:

| Before | After |
|---|---|
| `h.pool.Exec(ctx, sql, args)` | `tenant.Exec(ctx, h.pool, orgID, sql, args)` or wrap in `tenant.TxUser` |
| `db.WithRLS(ctx, pool, user.UserID, user.OrgID, func(ctx, conn) error {...})` | `tenant.TxUser(ctx, pool, user.OrgID, user.UserID, func(ctx, tx pgx.Tx) error {...})` |
| `conn.Query`, `conn.Exec` (inside WithRLS) | `tx.Query`, `tx.Exec` |
| `SET LOCAL app.current_org_id = '<id>'` (interpolated) | handled automatically by `tenant.TxUser` |
| `pool.QueryRow(ctx, sql).Scan(&x)` | `tenant.QueryRow(ctx, pool, orgID, sql).Scan(&x)` |

The `pkg/db.WithRLS` helper is deprecated (kept only for in-flight
branches). New code should never reference it.

---

## 5. When to add to the lint allowlist

`pkg/tenant/lint_test.go`'s `allowedDirectPoolCallers` map lists
packages that legitimately do direct pool access. Add an entry only
when:

- The code is **pre-session** (OIDC callback, login handler), OR
- The code is **platform-admin cross-tenant** (audit export, updater), OR
- The code runs **under a BYPASSRLS role** (audit-service, workers
  after Wave 3).

Every new entry needs a comment explaining WHY. Security review
audits this list quarterly.

---

## 6. Further reading

- Phase 7 plan: `docs/superpowers/plans/2026-04-18-phase7-data-security.md`
- Operator runbook: `docs/data-security-operator-runbook.md`
- Secret path catalog: `docs/secret-path-catalog.md`
- Package docs: `pkg/tenant/tenant.go`, `pkg/crypto/envelope.go`, `pkg/secrets/resolver.go`
