package tenant

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Scope pins a pool + orgID pair so call sites that do many tenant-
// scoped reads in a row don't repeat the orgID argument. Construct once
// per request (usually from the Principal) and pass downward.
//
// A Scope value with empty OrgID is not usable; every method would
// return ErrNoTenant. The constructor refuses the empty case so the
// failure surfaces early at the handler boundary.
type Scope struct {
	pool  *pgxpool.Pool
	orgID string
}

// NewScope constructs a Scope. Returns ErrNoTenant on empty orgID.
func NewScope(pool *pgxpool.Pool, orgID string) (Scope, error) {
	if orgID == "" {
		return Scope{}, ErrNoTenant
	}
	return Scope{pool: pool, orgID: orgID}, nil
}

// OrgID returns the pinned org. Exposed mainly for logging.
func (s Scope) OrgID() string { return s.orgID }

// Tx delegates to the package-level Tx with the pinned orgID.
func (s Scope) Tx(ctx context.Context,
	fn func(ctx context.Context, tx pgx.Tx) error) error {
	return Tx(ctx, s.pool, s.orgID, fn)
}

// Exec delegates to the package-level Exec.
func (s Scope) Exec(ctx context.Context, sql string,
	args ...any) (pgconn.CommandTag, error) {
	return Exec(ctx, s.pool, s.orgID, sql, args...)
}

// QueryRow delegates to the package-level QueryRow.
func (s Scope) QueryRow(ctx context.Context, sql string, args ...any) rowFunc {
	return QueryRow(ctx, s.pool, s.orgID, sql, args...)
}
