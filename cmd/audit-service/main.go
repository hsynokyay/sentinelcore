package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/audit"
	"github.com/sentinelcore/sentinelcore/internal/audit/partition"
	pkgaudit "github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/db"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("audit-service")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to PostgreSQL
	maxConns, _ := strconv.Atoi(getEnv("DB_MAX_CONNS", "10"))
	if maxConns < 1 {
		maxConns = 10
	}
	dbPort, _ := strconv.Atoi(getEnv("DB_PORT", "5432"))
	if dbPort == 0 {
		dbPort = 5432
	}
	pool, err := db.NewPool(ctx, db.Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     dbPort,
		Database: getEnv("DB_NAME", "sentinelcore"),
		User:     getEnv("DB_USER", "sentinelcore"),
		Password: getEnv("DB_PASSWORD", "dev-password"),
		MaxConns: maxConns,
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

	// Partition manager: keeps a rolling window of monthly partitions so
	// a boundary-crossing audit row never lands in audit_log_default.
	// Runs once at startup, then daily. Tuneable via env for ops testing.
	monthsAhead, _ := strconv.Atoi(getEnv("AUDIT_PARTITION_MONTHS_AHEAD", "2"))
	partInterval, err := time.ParseDuration(getEnv("AUDIT_PARTITION_INTERVAL", "24h"))
	if err != nil {
		partInterval = 24 * time.Hour
	}
	pm := partition.New(pool, logger)
	if _, err := pm.EnsureRollingWindow(ctx, monthsAhead); err != nil {
		// Non-fatal: migration 033 already seeded the window, cron will retry.
		logger.Error().Err(err).Msg("initial partition ensure failed; cron will retry")
	} else {
		logger.Info().Int("months_ahead", monthsAhead).Msg("audit partitions: initial window ok")
	}
	go pm.RunDaily(ctx, monthsAhead, partInterval)

	// Start consumer. Mode is chosen by env:
	//   AUDIT_CONSUMER_MODE=legacy (default) → pre-chain write path; rows
	//       land with previous_hash='' / entry_hash=''. Verifier reports
	//       'partial' outcome — expected during transition.
	//   AUDIT_CONSUMER_MODE=hmac → chained, tamper-evident write path.
	//       Requires AUDIT_HMAC_KEY_B64 to be set to a 32-byte base64 key.
	writer := audit.NewWriter(pool)
	consumer := audit.NewConsumer(js, writer, logger)

	mode := getEnv("AUDIT_CONSUMER_MODE", "legacy")
	switch mode {
	case "legacy":
		logger.Info().Msg("audit consumer: legacy write path (no chain)")
	case "hmac":
		keys, err := pkgaudit.NewEnvKeyResolver()
		if err != nil {
			logger.Fatal().Err(err).Msg("AUDIT_CONSUMER_MODE=hmac but key resolver failed")
		}
		hw := audit.NewHMACWriter(pool, keys)
		consumer.WithHMACWriter(hw)
		logger.Info().
			Int("key_version", keys.CurrentVersion()).
			Str("fingerprint_prefix", keys.Fingerprint()[:16]).
			Msg("audit consumer: HMAC chained write path")
	default:
		logger.Fatal().Str("mode", mode).Msg("AUDIT_CONSUMER_MODE must be 'legacy' or 'hmac'")
	}

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
