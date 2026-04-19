package tenant

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Scope pins a pool + orgID + optional userID tuple so call sites that
// do many tenant-scoped reads in a row don't repeat the same arguments.
// Construct once per request (usually from the Principal) and pass
// downward.
//
// A Scope value with empty OrgID is not usable; every method would
// return ErrNoTenant. The constructor refuses the empty case so the
// failure surfaces early at the handler boundary.
type Scope struct {
	pool   *pgxpool.Pool
	orgID  string
	userID string
}

// NewScope constructs an org-only Scope. Prefer ForUser when a logged-in
// user is driving the call — RLS policies on governance/team tables
// require app.current_user_id too.
func NewScope(pool *pgxpool.Pool, orgID string) (Scope, error) {
	if orgID == "" {
		return Scope{}, ErrNoTenant
	}
	return Scope{pool: pool, orgID: orgID}, nil
}

// ForUser constructs a Scope with both org_id and user_id set. This is
// the canonical constructor for handler code path — the resulting
// Scope satisfies every RLS policy in the schema.
func ForUser(pool *pgxpool.Pool, orgID, userID string) (Scope, error) {
	if orgID == "" {
		return Scope{}, ErrNoTenant
	}
	return Scope{pool: pool, orgID: orgID, userID: userID}, nil
}

// OrgID returns the pinned org. Exposed mainly for logging.
func (s Scope) OrgID() string { return s.orgID }

// UserID returns the pinned user (may be empty for org-only scopes).
func (s Scope) UserID() string { return s.userID }

// Tx delegates to the package-level TxUser with the pinned ids.
func (s Scope) Tx(ctx context.Context,
	fn func(ctx context.Context, tx pgx.Tx) error) error {
	return TxUser(ctx, s.pool, s.orgID, s.userID, fn)
}

// Exec runs a single statement inside a Scope-bound transaction.
func (s Scope) Exec(ctx context.Context, sql string,
	args ...any) (pgconn.CommandTag, error) {
	var tag pgconn.CommandTag
	err := s.Tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		t, err := tx.Exec(ctx, sql, args...)
		tag = t
		return err
	})
	return tag, err
}

// QueryRow is the single-row read shortcut, Scope-bound.
func (s Scope) QueryRow(ctx context.Context, sql string, args ...any) rowFunc {
	return func(dst ...any) error {
		return s.Tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, sql, args...).Scan(dst...)
		})
	}
}
