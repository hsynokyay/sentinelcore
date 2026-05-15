// cmd/sla-worker — dedicated SLA breach + at-risk detection daemon.
//
// Mirrors cmd/retention-worker/main.go: pgxpool, NATS JetStream, signal-based
// shutdown. Configurable via env:
//
//	DATABASE_URL          (default: postgres://sentinel@localhost/sentinel)
//	NATS_URL              (default: nats://localhost:4222)
//	SLA_WORKER_INTERVAL   (default: 1h, accepts time.ParseDuration syntax)
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/governance/slaworker"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "sla-worker").Logger()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := pgxpool.New(ctx, getEnv("DATABASE_URL", "postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable"))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: getEnv("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to NATS")
	}
	defer nc.Close()

	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure NATS streams")
	}

	interval := time.Hour
	if v := os.Getenv("SLA_WORKER_INTERVAL"); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil && d > 0 {
			interval = d
		} else {
			logger.Warn().Str("SLA_WORKER_INTERVAL", v).Msg("invalid duration; falling back to 1h")
		}
	}

	logger.Info().Dur("interval", interval).Msg("sla worker started")

	worker := slaworker.New(pool, js)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// First cycle immediately so a freshly-deployed worker doesn't wait an
	// interval to surface backlog breaches.
	runCycle(ctx, worker, &logger)

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("sla worker shutting down")
			return
		case <-ticker.C:
			runCycle(ctx, worker, &logger)
		}
	}
}

func runCycle(ctx context.Context, w *slaworker.Worker, logger *zerolog.Logger) {
	if err := w.RunOnce(ctx); err != nil {
		logger.Error().Err(err).Msg("sla worker cycle failed")
		return
	}
	res := w.LastResult()
	logger.Info().
		Int("violations", res.Violations).
		Int("warnings", res.Warnings).
		Dur("duration", res.EndedAt.Sub(res.StartedAt)).
		Msg("sla worker cycle complete")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
