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
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ErrNotFound is returned by Store lookups when no row matches.
var ErrNotFound = errors.New("risk: not found")

// The concrete store methods are implemented in Chunk 6. This skeleton
// exists so that earlier chunks can reference the Store type without
// introducing compile errors.
func (s *Store) ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}
