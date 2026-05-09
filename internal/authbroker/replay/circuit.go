package replay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/metrics"
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
	// timestamp, error message, and (when non-empty) appends the screenshot
	// MinIO object key to the row's screenshot_refs JSONB array.
	RecordFailure(ctx context.Context, bundleID uuid.UUID, errMsg, screenshotRef string) error
	// Reset clears the failure counter and screenshot refs, closing the
	// circuit.
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
			metrics.CircuitState.WithLabelValues(bundleID.String()).Set(0)
			return false, nil
		}
		return false, fmt.Errorf("circuit: query: %w", err)
	}
	open := n >= CircuitFailureThreshold
	if open {
		metrics.CircuitState.WithLabelValues(bundleID.String()).Set(1)
	} else {
		metrics.CircuitState.WithLabelValues(bundleID.String()).Set(0)
	}
	return open, nil
}

// RecordFailure increments the failure counter, creating the row if absent.
// When screenshotRef is non-empty it is appended to the row's screenshot_refs
// JSONB array; an empty string preserves the existing array unchanged.
func (s *PostgresCircuitStore) RecordFailure(ctx context.Context, bundleID uuid.UUID, errMsg, screenshotRef string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO dast_replay_failures
		    (bundle_id, consecutive_failures, last_failure_at, last_error, screenshot_refs)
		VALUES ($1, 1, $2, $3,
		        CASE WHEN $4 = '' THEN '[]'::jsonb ELSE jsonb_build_array($4) END)
		ON CONFLICT (bundle_id) DO UPDATE
		SET consecutive_failures = dast_replay_failures.consecutive_failures + 1,
		    last_failure_at      = EXCLUDED.last_failure_at,
		    last_error           = EXCLUDED.last_error,
		    screenshot_refs      = CASE
		                              WHEN $4 = '' THEN dast_replay_failures.screenshot_refs
		                              ELSE dast_replay_failures.screenshot_refs || jsonb_build_array($4)
		                          END`,
		bundleID, time.Now(), errMsg, screenshotRef)
	if err != nil {
		return fmt.Errorf("circuit: record failure: %w", err)
	}
	return nil
}

// Reset clears the failure counter and screenshot refs for bundleID. Missing
// rows are a no-op.
func (s *PostgresCircuitStore) Reset(ctx context.Context, bundleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE dast_replay_failures
		    SET consecutive_failures = 0,
		        screenshot_refs      = '[]'::jsonb
		    WHERE bundle_id = $1`,
		bundleID)
	if err != nil {
		return fmt.Errorf("circuit: reset: %w", err)
	}
	return nil
}
