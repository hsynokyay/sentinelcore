// Package partition manages monthly partitions of audit.audit_log.
//
// The audit-worker runs EnsureRollingWindow daily. It creates the
// NEXT two months ahead (idempotent via migration 033's ensure_partition
// function) so a clock skew, missed cron, or brief outage on the last
// day of the month never routes an audit row into the default partition.
//
// Partition REMOVAL is deliberately NOT automated. Detaching and archiving
// old partitions is a compliance-significant action: it touches legal-hold
// windows and retention policy. This package exposes Detach + Archive as
// separate, operator-invoked CLIs — see docs/audit-operator-runbook.md.
package partition

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Manager drives partition lifecycle. Safe for concurrent use.
type Manager struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

func New(pool *pgxpool.Pool, logger zerolog.Logger) *Manager {
	return &Manager{pool: pool, logger: logger}
}

// EnsureRollingWindow creates partitions for [now, now + monthsAhead]. Each
// call is safe and idempotent — PG's CREATE TABLE IF NOT EXISTS takes the
// slow path only for new partitions.
//
// Returns the number of partitions created (including ones that already
// existed — we report the full examined window so operators have a clear
// signal that the cron is alive even when there's nothing to do).
func (m *Manager) EnsureRollingWindow(ctx context.Context, monthsAhead int) (examined int, err error) {
	if monthsAhead < 0 {
		return 0, fmt.Errorf("partition: monthsAhead must be non-negative")
	}
	for i := 0; i <= monthsAhead; i++ {
		t := time.Now().UTC().AddDate(0, i, 0)
		monthStart := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		if _, err := m.pool.Exec(ctx,
			`SELECT audit.ensure_partition($1::date)`,
			monthStart); err != nil {
			return examined, fmt.Errorf(
				"ensure_partition %s: %w",
				monthStart.Format("2006-01"), err)
		}
		examined++
	}
	return examined, nil
}

// List returns the names of existing (non-default) monthly partitions,
// newest first. Used by the hourly verifier scheduler and by ops tooling.
func (m *Manager) List(ctx context.Context) ([]string, error) {
	rows, err := m.pool.Query(ctx, `SELECT partition_name FROM audit.list_partitions()`)
	if err != nil {
		return nil, fmt.Errorf("list partitions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// RunDaily is a blocking loop suitable for goroutine launch from main().
// Wakes up once per interval, ensures the rolling window, sleeps.
// Cancellation via ctx is clean: the current iteration completes, then
// the loop exits.
//
// The default monthsAhead=2 leaves a comfortable margin; bumping it
// doesn't cost anything except slightly longer ensure runs.
func (m *Manager) RunDaily(ctx context.Context, monthsAhead int, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if monthsAhead <= 0 {
		monthsAhead = 2
	}

	run := func() {
		n, err := m.EnsureRollingWindow(ctx, monthsAhead)
		if err != nil {
			m.logger.Error().Err(err).Msg("audit partition: ensure rolling window failed")
			return
		}
		m.logger.Info().Int("months_examined", n).Msg("audit partition: rolling window ok")
	}

	run() // run once at startup
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
