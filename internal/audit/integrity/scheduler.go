package integrity

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Scheduler runs periodic chain verification over the monthly partitions.
//
// Policy (Phase 6 Chunk 9):
//   - "Warm" partitions (current month + last 3) verified in full every hour.
//   - Older partitions verified via a random-sample + boundary-row check
//     daily (not implemented yet — current scheduler only does the warm path).
//
// Each run writes one row per partition to audit.integrity_checks. The
// verifier itself logs pass/fail/partial; the scheduler's job is just to
// iterate and surface Prometheus counters.
type Scheduler struct {
	pool     *pgxpool.Pool
	verifier *Verifier
	logger   zerolog.Logger
}

func NewScheduler(pool *pgxpool.Pool, verifier *Verifier, logger zerolog.Logger) *Scheduler {
	return &Scheduler{pool: pool, verifier: verifier, logger: logger}
}

// RunHourly blocks on a ticker. Cancellable via ctx; the current run
// completes before the loop exits.
//
// interval <= 0 → 1 hour. warmMonths <= 0 → 4 (current + last 3).
func (s *Scheduler) RunHourly(ctx context.Context, interval time.Duration, warmMonths int) {
	if interval <= 0 {
		interval = time.Hour
	}
	if warmMonths <= 0 {
		warmMonths = 4
	}

	runOnce := func() {
		partitions, err := s.warmPartitions(ctx, warmMonths)
		if err != nil {
			s.logger.Error().Err(err).Msg("integrity scheduler: list partitions")
			return
		}
		for _, p := range partitions {
			res, err := s.verifier.VerifyPartition(ctx, p)
			ev := s.logger.Info()
			if err != nil || res.Outcome == OutcomeError || res.Outcome == OutcomeFail {
				ev = s.logger.Error()
			}
			ev.
				Str("partition", p).
				Str("outcome", string(res.Outcome)).
				Int64("rows", res.RowsScanned).
				Int64("failed_row_id", res.FailedRowID).
				Str("error", res.ErrorMessage).
				Msg("integrity check")
		}
	}

	runOnce() // immediate run at startup so the first pass doesn't wait an hour
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runOnce()
		}
	}
}

// warmPartitions returns the N most recent monthly partition names.
// Newest-first, so the current month is verified before the older ones.
func (s *Scheduler) warmPartitions(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT partition_name FROM audit.list_partitions() LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("warmPartitions: %w", err)
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
