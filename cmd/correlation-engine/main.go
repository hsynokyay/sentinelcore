// Command correlation-engine runs the SentinelCore risk correlation worker.
// It subscribes to scan.status.update, debounces per project, rebuilds
// risk clusters in PostgreSQL, and exits on SIGINT/SIGTERM.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/risk"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("risk-worker")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dsn := getEnv("DATABASE_URL", "postgres://sentinelcore:dev-password@localhost:5432/sentinelcore")
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		logger.Fatal().Err(err).Msg("pg connect failed")
	}
	defer pool.Close()

	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: getEnv("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("nats connect failed")
	}
	defer nc.Close()

	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("ensure streams failed")
	}

	worker := risk.NewWorker(js, pool, logger)
	logger.Info().Msg("risk correlation worker starting")
	if err := worker.Run(ctx); err != nil {
		logger.Fatal().Err(err).Msg("worker exited with error")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
