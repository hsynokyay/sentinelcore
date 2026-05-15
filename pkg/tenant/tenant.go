// Package tenant centralises multi-tenant SQL access. Every state-
// changing handler routes through tenant.Tx instead of calling
// pool.Query / pool.Exec directly; tenant.Tx guarantees
//
//   1. a transaction is open,
//   2. app.current_org_id is set to the caller's org (local-only),
//   3. the orgID is non-empty (fail-fast on bugs).
//
// The postgres RLS policies installed by Phase 6 + Phase 7 Wave 3 read
// app.current_org_id. Running inside tenant.Tx is THE supported way to
// satisfy them.
//
// Direct pool.Query/Exec against tenant tables is discouraged; a static
// lint (lint_test.go) rejects the pattern outside explicit allowlist
// paths.
package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoTenant is returned by Tx when orgID is empty. Catch-and-panic in
// handlers is the recommended pattern — an empty orgID in a tenant-
// scoped call site means the caller forgot to populate it from the
// Principal, which is a programming bug.
var ErrNoTenant = errors.New("tenant: empty org_id")

// ErrNotVisible is returned by validators when a resource exists but
// belongs to a different tenant. Handlers MUST surface this as HTTP 404,
// NOT 403 — distinguishing "forbidden" from "not found" is a leak
// vector (plan §4.4 anti-footgun #3).
var ErrNotVisible = errors.New("tenant: resource not visible to caller")

// Tx opens a transaction, sets the session-local tenancy context, and
// runs fn. On fn error or panic the transaction rolls back; on success
// it commits.
//
// orgID must be a non-empty UUID string. Tx does NOT validate UUID
// format (that's the handler's auth layer); it DOES refuse empty.
//
// app.current_user_id is NOT set — use TxUser when the query touches
// a table whose RLS policy checks user_id (governance.*, team_memberships).
func Tx(ctx context.Context, pool *pgxpool.Pool, orgID string,
	fn func(ctx context.Context, tx pgx.Tx) error) error {
	return TxUser(ctx, pool, orgID, "", fn)
}

// TxUser is Tx plus app.current_user_id. userID may be empty for
// org-only contexts (audit writer, platform admin); policies that
// reference app.current_user_id will then see '' and typically deny.
// Passing the user_id is the correct default when a logged-in user is
// driving the call.
func TxUser(ctx context.Context, pool *pgxpool.Pool, orgID, userID string,
	fn func(ctx context.Context, tx pgx.Tx) error) error {

	if orgID == "" {
		return ErrNoTenant
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// set_config with is_local=true limits the binding to this
		// transaction — another query in the same connection after
		// commit sees no residual setting.
		if _, err := tx.Exec(ctx,
			`SELECT set_config('app.current_org_id', $1, true)`,
			orgID); err != nil {
			return fmt.Errorf("tenant: set org: %w", err)
		}
		if userID != "" {
			if _, err := tx.Exec(ctx,
				`SELECT set_config('app.current_user_id', $1, true)`,
				userID); err != nil {
				return fmt.Errorf("tenant: set user: %w", err)
			}
		}
		return fn(ctx, tx)
	})
}

// TxGlobal is the explicit escape hatch for platform-admin cross-tenant
// reads (audit export, reporting). It sets BOTH app.current_org_id
// (empty, so RLS would filter everything) AND app.audit_global_read=true
// (bypass gate for the audit reader policy). Use SPARINGLY — every call
// site is noise on the security review checklist.
func TxGlobal(ctx context.Context, pool *pgxpool.Pool,
	fn func(ctx context.Context, tx pgx.Tx) error) error {

	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`SELECT set_config('app.audit_global_read', 'true', true)`); err != nil {
			return fmt.Errorf("tenant: set global: %w", err)
		}
		return fn(ctx, tx)
	})
}

// Exec is the single-statement convenience wrapper — opens a short
// transaction, sets the tenant var, runs the statement. Returns the
// raw CommandTag for RowsAffected() inspection.
//
// For multi-statement flows, prefer Tx so both run in the same tx.
func Exec(ctx context.Context, pool *pgxpool.Pool, orgID, sql string,
	args ...any) (pgconn.CommandTag, error) {

	var tag pgconn.CommandTag
	err := Tx(ctx, pool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		t, err := tx.Exec(ctx, sql, args...)
		tag = t
		return err
	})
	return tag, err
}

// QueryRow is the single-row read shortcut. The returned pgx.Row only
// exposes Scan; Scan errors surface as-is from Tx.
func QueryRow(ctx context.Context, pool *pgxpool.Pool, orgID, sql string,
	args ...any) rowFunc {
	return func(dst ...any) error {
		return Tx(ctx, pool, orgID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, sql, args...).Scan(dst...)
		})
	}
}

// rowFunc adapts a tx-scoped Scan into the pgx.Row interface without
// forcing callers to see the tx.
type rowFunc func(dst ...any) error

// Scan matches pgx.Row.
func (r rowFunc) Scan(dst ...any) error { return r(dst...) }
