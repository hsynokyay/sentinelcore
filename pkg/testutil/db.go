//go:build integration

package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewTestDB creates a temporary test database connection.
// Connects to the Docker Compose PostgreSQL instance.
// Tests using this helper must be tagged with //go:build integration
func NewTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dsn := "postgres://sentinelcore:dev-password@localhost:5432/sentinelcore?sslmode=disable"

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("testutil.NewTestDB: connect: %v", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("testutil.NewTestDB: ping: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
	})

	return pool
}
