package integrity

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/pkg/observability"
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
			// Skip partitions that don't exist yet (warmMonths window may
			// reach back past migration 033's seed start). 42P01 from the
			// verifier is not an integrity failure, just "no data".
			if exists, err := s.partitionExists(ctx, p); err != nil {
				s.logger.Error().Err(err).Str("partition", p).Msg("integrity check: exists probe")
				continue
			} else if !exists {
				s.logger.Debug().Str("partition", p).Msg("integrity check: partition absent, skipped")
				continue
			}
			res, _ := s.verifier.VerifyPartition(ctx, p)

			// Prometheus surface: operators alert on
			// rate(sentinelcore_audit_integrity_check_total{outcome="fail"}[1h])>0.
			observability.AuditIntegrityChecks.WithLabelValues(p, string(res.Outcome)).Inc()

			// Fail + error are pager events. The `alert` tag is a marker
			// the log-shipper picks up and routes to pagerduty via Loki
			// regex (see docs/audit-operator-runbook.md §integrity_failed).
			ev := s.logger.Info()
			if res.Outcome == OutcomeError || res.Outcome == OutcomeFail {
				ev = s.logger.Error().Str("alert", "audit_integrity_failed")
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

// partitionExists returns true if audit.<name> is a tracked partition.
// Uses pg_class, which is cheap and local to the catalog.
func (s *Scheduler) partitionExists(ctx context.Context, name string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM pg_class c
		    JOIN pg_namespace n ON n.oid = c.relnamespace
		    WHERE n.nspname = 'audit' AND c.relname = $1
		)`, name).Scan(&exists)
	return exists, err
}

// warmPartitions returns the partition names for [now-warmMonths+1, now],
// newest (current) first. This is write-location-aware: list_partitions()
// orders lexicographically, so the 13-month rolling seed puts future
// partitions first — NOT what "warm" means for our purposes. A warm
// partition is one that receives (or recently received) writes.
//
// Resolution is based on UTC time, matching the partition seeder.
func (s *Scheduler) warmPartitions(_ context.Context, warmMonths int) ([]string, error) {
	if warmMonths <= 0 {
		warmMonths = 4
	}
	out := make([]string, 0, warmMonths)
	now := time.Now().UTC()
	for i := 0; i < warmMonths; i++ {
		t := time.Date(now.Year(), now.Month()-time.Month(i), 1, 0, 0, 0, 0, time.UTC)
		out = append(out, fmt.Sprintf("audit_log_%04d%02d", t.Year(), int(t.Month())))
	}
	return out, nil
}
