package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WithRLS acquires a connection from the pool, sets RLS session variables,
// and executes the given function. Variables are cleared on return.
func WithRLS(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, fn func(ctx context.Context, conn *pgxpool.Conn) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("db.WithRLS: acquire conn: %w", err)
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, fmt.Sprintf("SET LOCAL app.current_user_id = '%s'", userID))
	if err != nil {
		return fmt.Errorf("db.WithRLS: set user_id: %w", err)
	}

	_, err = conn.Exec(ctx, fmt.Sprintf("SET LOCAL app.current_org_id = '%s'", orgID))
	if err != nil {
		return fmt.Errorf("db.WithRLS: set org_id: %w", err)
	}

	return fn(ctx, conn)
}
