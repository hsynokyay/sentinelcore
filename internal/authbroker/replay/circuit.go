package replay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CircuitFailureThreshold is the number of consecutive replay failures after
// which the per-bundle circuit is considered open.
const CircuitFailureThreshold = 3

// CircuitStore tracks per-bundle replay failure counters used to short-circuit
// repeated calls when a bundle is unhealthy. Implementations must be safe for
// concurrent use.
type CircuitStore interface {
	// IsOpen returns true when the circuit for bundleID has reached the
	// failure threshold. Missing rows are treated as closed.
	IsOpen(ctx context.Context, bundleID uuid.UUID) (bool, error)
	// RecordFailure increments the bundle's failure counter and records the
	// timestamp + error message.
	RecordFailure(ctx context.Context, bundleID uuid.UUID, errMsg string) error
	// Reset clears the failure counter, closing the circuit.
	Reset(ctx context.Context, bundleID uuid.UUID) error
}

// PostgresCircuitStore is a CircuitStore backed by the dast_replay_failures
// table.
type PostgresCircuitStore struct {
	pool *pgxpool.Pool
}

// NewCircuitStore returns a Postgres-backed CircuitStore.
func NewCircuitStore(pool *pgxpool.Pool) *PostgresCircuitStore {
	return &PostgresCircuitStore{pool: pool}
}

// IsOpen reports whether the circuit for bundleID is open (>= threshold
// consecutive failures). Missing rows are treated as zero failures (closed).
func (s *PostgresCircuitStore) IsOpen(ctx context.Context, bundleID uuid.UUID) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT consecutive_failures FROM dast_replay_failures WHERE bundle_id = $1`,
		bundleID,
	).Scan(&n)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("circuit: query: %w", err)
	}
	return n >= CircuitFailureThreshold, nil
}

// RecordFailure increments the failure counter, creating the row if absent.
func (s *PostgresCircuitStore) RecordFailure(ctx context.Context, bundleID uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO dast_replay_failures (bundle_id, consecutive_failures, last_failure_at, last_error)
		VALUES ($1, 1, $2, $3)
		ON CONFLICT (bundle_id) DO UPDATE
		SET consecutive_failures = dast_replay_failures.consecutive_failures + 1,
		    last_failure_at      = EXCLUDED.last_failure_at,
		    last_error           = EXCLUDED.last_error`,
		bundleID, time.Now(), errMsg)
	if err != nil {
		return fmt.Errorf("circuit: record failure: %w", err)
	}
	return nil
}

// Reset clears the failure counter for bundleID. Missing rows are a no-op.
func (s *PostgresCircuitStore) Reset(ctx context.Context, bundleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE dast_replay_failures SET consecutive_failures = 0 WHERE bundle_id = $1`,
		bundleID)
	if err != nil {
		return fmt.Errorf("circuit: reset: %w", err)
	}
	return nil
}
