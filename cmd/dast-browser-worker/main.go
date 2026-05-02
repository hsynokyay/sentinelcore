// Command dast-browser-worker runs the SentinelCore browser-based DAST worker.
// It receives browser scan jobs via NATS JetStream, executes them with
// hardened Chrome instances and three-layer scope enforcement, and publishes
// signed results.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/internal/browser"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("dast-browser-worker")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to NATS.
	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: getEnv("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("NATS connect failed")
	}
	defer nc.Close()

	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure streams")
	}

	// MSG_SIGNING_KEY is required for HMAC-signed messages.
	signingKeyStr := getEnv("MSG_SIGNING_KEY", "")
	if signingKeyStr == "" {
		logger.Fatal().Msg("MSG_SIGNING_KEY environment variable is required")
	}
	signingKey := []byte(signingKeyStr)

	// Create auth broker and browser worker.
	broker := authbroker.NewBroker(logger)
	worker := browser.NewBrowserWorker(getEnv("WORKER_ID", ""), broker, logger)

	// Start NATS-connected worker.
	natsWorker := browser.NewNATSBrowserWorker(js, worker, signingKey, logger)

	logger.Info().Msg("browser DAST worker starting")
	if err := natsWorker.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("worker failed")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
