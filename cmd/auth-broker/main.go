// Command auth-broker runs the SentinelCore Auth Session Broker.
// It manages authenticated sessions for DAST scanning via NATS JetStream,
// supporting multiple auth strategies (bearer, OAuth2 CC, form login, API key).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("auth-broker")
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

	// Create broker and NATS handler
	broker := authbroker.NewBroker(logger)
	handler := authbroker.NewNATSHandler(broker, js, logger)

	logger.Info().Msg("Auth Session Broker starting")
	if err := handler.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("auth broker failed")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
