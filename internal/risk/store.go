package risk

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the persistence layer for the risk package. All PostgreSQL
// interactions go through this type so the correlator can be tested
// against a stub in unit tests and the real pool in integration tests.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a Store backed by the given pgx connection pool.
// Panics if pool is nil — the risk package requires a live database.
func NewStore(pool *pgxpool.Pool) *Store {
	if pool == nil {
		panic("risk: NewStore called with nil pool")
	}
	return &Store{pool: pool}
}

// ErrNotFound is returned by Store lookups when no row matches.
var ErrNotFound = errors.New("risk: not found")

// Ping verifies the database connection. Used by health checks and by
// later chunks as a cheap smoke test before beginning a correlation run.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}
