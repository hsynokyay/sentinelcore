// Command correlation-engine runs the SentinelCore Correlation Engine.
// It consumes SAST and DAST findings from NATS JetStream, deduplicates,
// cross-correlates, computes risk scores, and publishes unified findings.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sentinelcore/sentinelcore/internal/correlation"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("correlation-engine")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to NATS
	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: getEnv("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("NATS connect failed")
	}
	defer nc.Close()

	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure streams")
	}

	signingKeyStr := getEnv("MSG_SIGNING_KEY", "")
	if signingKeyStr == "" {
		logger.Fatal().Msg("MSG_SIGNING_KEY environment variable is required")
	}

	// Create engine with in-memory store (replaced with PostgreSQL store in production)
	store := correlation.NewMemStore()
	engine := correlation.NewEngine(store, logger)
	handler := correlation.NewNATSHandler(engine, js, []byte(signingKeyStr), logger)

	logger.Info().Msg("Correlation Engine starting")
	if err := handler.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("correlation engine failed")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
