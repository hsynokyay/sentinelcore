// Command sla-sweep is a periodic worker that reconciles
// governance.sla_deadlines against the live finding state:
//
//   1. Any unresolved row whose deadline_at < now AND breached_at
//      IS NULL is stamped breached_at=now and emits
//      sla.deadline.breached audit event.
//   2. Any row whose underlying finding is in a closed state is
//      stamped resolved_at=now (if not already) and emits
//      sla.deadline.resolved.
//   3. Rows past their escalation window (policy
//      escalate_after_hours since breached_at) get escalated_at set
//      + sla.deadline.escalated audit.
//
// Runs under the sentinelcore_worker DB role (Phase 7 split). Uses
// TxGlobal for cross-tenant reconciliation — sweep doesn't know a
// tenant context up front.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/pkg/db"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("sla-sweep")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := db.NewPool(ctx, dbConfig())
	if err != nil {
		logger.Fatal().Err(err).Msg("connect db")
	}
	defer pool.Close()

	interval := envDuration("SLA_SWEEP_INTERVAL", 15*time.Minute)
	// One-shot option for running via cron/systemd timer instead of
	// keeping a process alive. --once exits after the first pass.
	once := hasArg("--once")

	logger.Info().Dur("interval", interval).Bool("once", once).Msg("sla-sweep starting")

	run := func() {
		if err := sweep(ctx, pool, logger); err != nil {
			logger.Error().Err(err).Msg("sweep failed")
		}
	}

	// Immediate run so a systemd --once invocation does useful work.
	run()
	if once {
		return
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("sla-sweep shutting down")
			return
		case <-t.C:
			run()
		}
	}
}

// sweep performs the three-stage reconciliation in three short txs.
// Cross-tenant by design; the worker role has BYPASSRLS (Phase 7).
func sweep(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger) error {
	// 1. Stamp breaches.
	var breached []breachedRow
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			UPDATE governance.sla_deadlines
			   SET breached_at = now()
			 WHERE resolved_at IS NULL
			   AND breached_at IS NULL
			   AND deadline_at < now()
			RETURNING finding_id, org_id, project_id, severity`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r breachedRow
			if err := rows.Scan(&r.FindingID, &r.OrgID, &r.ProjectID, &r.Severity); err != nil {
				return err
			}
			breached = append(breached, r)
		}
		return rows.Err()
	})
	if err != nil {
		return fmt.Errorf("stamp breaches: %w", err)
	}

	// 2. Stamp resolutions — any deadline whose finding is closed.
	var resolved []breachedRow
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			UPDATE governance.sla_deadlines d
			   SET resolved_at = now()
			  FROM findings.findings f
			 WHERE f.id = d.finding_id
			   AND d.resolved_at IS NULL
			   AND f.status IN ('resolved','closed','false_positive')
			RETURNING d.finding_id, d.org_id, d.project_id, d.severity`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r breachedRow
			if err := rows.Scan(&r.FindingID, &r.OrgID, &r.ProjectID, &r.Severity); err != nil {
				return err
			}
			resolved = append(resolved, r)
		}
		return rows.Err()
	})
	if err != nil {
		return fmt.Errorf("stamp resolutions: %w", err)
	}

	// 3. Escalation: rows breached long enough ago (per policy) and
	//    not yet escalated. We compute the threshold in Go to avoid
	//    a complex join; it's bounded by the breached-set which is
	//    already small (today's newly-overdue rows).
	var escalated []breachedRow
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			UPDATE governance.sla_deadlines d
			   SET escalated_at = now()
			  FROM governance.sla_policies p
			 WHERE p.id = d.policy_id
			   AND d.resolved_at  IS NULL
			   AND d.breached_at  IS NOT NULL
			   AND d.escalated_at IS NULL
			   AND p.escalate_after_hours IS NOT NULL
			   AND d.breached_at + (p.escalate_after_hours * INTERVAL '1 hour') < now()
			RETURNING d.finding_id, d.org_id, d.project_id, d.severity`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r breachedRow
			if err := rows.Scan(&r.FindingID, &r.OrgID, &r.ProjectID, &r.Severity); err != nil {
				return err
			}
			escalated = append(escalated, r)
		}
		return rows.Err()
	})
	if err != nil {
		return fmt.Errorf("stamp escalations: %w", err)
	}

	// Audit event emission is deferred to a Wave 2 follow-up once
	// the sweep worker is wired to NATS. For now the DB-side
	// transitions are the authoritative record and downstream
	// consumers watch governance.sla_deadlines directly.

	logger.Info().
		Int("breached", len(breached)).
		Int("resolved", len(resolved)).
		Int("escalated", len(escalated)).
		Msg("sweep pass complete")
	_ = observability.NewLogger // keep import alive for future emit wiring
	return nil
}

type breachedRow struct {
	FindingID string
	OrgID     string
	ProjectID string
	Severity  string
}

// --- env + arg plumbing ---

func dbConfig() db.Config {
	return db.Config{
		Host:     envOrDefault("DB_HOST", "localhost"),
		Port:     envIntOrDefault("DB_PORT", 5432),
		Database: envOrDefault("DB_NAME", "sentinelcore"),
		User:     envOrDefault("DB_USER", "sentinelcore"),
		Password: envOrDefault("DB_PASSWORD", "dev-password"),
		MaxConns: 2,
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func hasArg(want string) bool {
	for _, a := range os.Args[1:] {
		if a == want {
			return true
		}
	}
	return false
}
