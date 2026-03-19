// Command dast-worker runs the SentinelCore DAST scan worker.
// It receives scan jobs via NATS JetStream, executes API-first DAST tests
// with scope enforcement, and publishes signed results.
package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/internal/dast"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("dast-worker")
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

	// Config
	concurrency := 10
	if v := getEnv("CONCURRENCY", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			concurrency = n
		}
	}
	timeout := 30 * time.Second
	if v := getEnv("REQUEST_TIMEOUT", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}
	signingKeyStr := getEnv("MSG_SIGNING_KEY", "")
	if signingKeyStr == "" {
		logger.Fatal().Msg("MSG_SIGNING_KEY environment variable is required")
	}
	signingKey := []byte(signingKeyStr)

	// Create broker and worker
	broker := authbroker.NewBroker(logger)
	worker := dast.NewWorker(dast.WorkerConfig{
		WorkerID:       getEnv("WORKER_ID", ""),
		MaxConcurrency: concurrency,
		RequestTimeout: timeout,
	}, broker, logger)

	// Start NATS-connected worker
	natsWorker := dast.NewNATSWorker(js, worker, signingKey, logger)

	logger.Info().Msg("DAST worker starting")
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
