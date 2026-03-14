package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sentinelcore/sentinelcore/internal/audit"
	"github.com/sentinelcore/sentinelcore/pkg/db"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("audit-service")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to PostgreSQL
	pool, err := db.NewPool(ctx, db.Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     5432,
		Database: getEnv("DB_NAME", "sentinelcore"),
		User:     getEnv("DB_USER", "sentinelcore"),
		Password: getEnv("DB_PASSWORD", "dev-password"),
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	// Connect to NATS
	nc, js, err := sc_nats.Connect(sc_nats.Config{
		URL: getEnv("NATS_URL", "nats://localhost:4222"),
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to NATS")
	}
	defer nc.Close()

	// Ensure streams exist
	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure streams")
	}

	// Health + metrics server
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", observability.HealthHandler())
		mux.Handle("/metrics", observability.MetricsHandler())
		port := getEnv("METRICS_PORT", "9090")
		logger.Info().Str("port", port).Msg("metrics server starting")
		if err := http.ListenAndServe(fmt.Sprintf(":%s", port), mux); err != nil {
			logger.Error().Err(err).Msg("metrics server failed")
		}
	}()

	// Start consumer
	writer := audit.NewWriter(pool)
	consumer := audit.NewConsumer(js, writer, logger)

	logger.Info().Msg("Audit Log Service starting")
	if err := consumer.Start(ctx); err != nil && err != context.Canceled {
		logger.Fatal().Err(err).Msg("consumer failed")
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
