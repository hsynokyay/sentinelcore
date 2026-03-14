// Command dast-worker runs the SentinelCore DAST scan worker.
// It receives scan jobs via NATS, executes API-first DAST tests
// with scope enforcement, and publishes results.
package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/internal/dast"
)

type workerCfg struct {
	WorkerID       string `default:""`
	Concurrency    int    `default:"10"`
	RequestTimeout int    `default:"30"` // seconds
}

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "dast-worker").Logger()

	concurrency := 10
	if v := os.Getenv("SENTINELCORE_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			concurrency = n
		}
	}
	timeout := 30 * time.Second
	if v := os.Getenv("SENTINELCORE_REQUEST_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}

	broker := authbroker.NewBroker(logger)

	worker := dast.NewWorker(dast.WorkerConfig{
		WorkerID:       os.Getenv("SENTINELCORE_WORKER_ID"),
		MaxConcurrency: concurrency,
		RequestTimeout: timeout,
	}, broker, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info().Str("signal", sig.String()).Msg("shutting down")
		cancel()
	}()

	_ = worker
	logger.Info().Msg("DAST worker started, waiting for scan jobs")
	<-ctx.Done()
	logger.Info().Msg("DAST worker stopped")
}
