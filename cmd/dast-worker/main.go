// Command dast-worker runs the SentinelCore DAST scan worker.
// It receives scan dispatches via NATS JetStream, resolves scan_jobs +
// targets + auth profiles from Postgres, runs endpoint discovery + active
// probes against the target, and persists findings + status updates back
// to the database. Status updates also publish to scan.status.update so the
// correlation engine keeps working unchanged.
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
	"github.com/sentinelcore/sentinelcore/pkg/crypto"
	"github.com/sentinelcore/sentinelcore/pkg/db"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("dast-worker")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Database — required so we can resolve scan_jobs/targets and persist findings.
	pool, err := db.NewPool(ctx, db.Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     getEnvInt("DB_PORT", 5432),
		Database: getEnv("DB_NAME", "sentinelcore"),
		User:     getEnv("DB_USER", "sentinelcore"),
		Password: getEnv("DB_PASSWORD", "dev-password"),
		MaxConns: getEnvInt("DB_MAX_CONNS", 5),
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("database connect failed")
	}
	defer pool.Close()
	logger.Info().Msg("connected to PostgreSQL")

	// NATS
	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: getEnv("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("NATS connect failed")
	}
	defer nc.Close()
	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure streams")
	}
	logger.Info().Msg("connected to NATS")

	// Worker config
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

	// Auth profile cipher (optional — only required for targets with auth profiles).
	var cipher *crypto.AESGCM
	if hexKey := getEnv("AUTH_PROFILE_ENCRYPTION_KEY", ""); hexKey != "" {
		key, err := crypto.DecodeHexKey(hexKey)
		if err != nil {
			logger.Fatal().Err(err).Msg("AUTH_PROFILE_ENCRYPTION_KEY invalid")
		}
		c, err := crypto.NewAESGCM(key)
		if err != nil {
			logger.Fatal().Err(err).Msg("AUTH_PROFILE_ENCRYPTION_KEY initialization failed")
		}
		cipher = c
		logger.Info().Msg("auth profile cipher initialized")
	} else {
		logger.Warn().Msg("AUTH_PROFILE_ENCRYPTION_KEY not set — targets with auth profiles will fail with explicit error")
	}

	// Build worker stack.
	broker := authbroker.NewBroker(logger)
	worker := dast.NewWorker(dast.WorkerConfig{
		WorkerID:       getEnv("WORKER_ID", ""),
		MaxConcurrency: concurrency,
		RequestTimeout: timeout,
	}, broker, logger)

	natsWorker := dast.NewNATSWorker(js, pool, worker, signingKey, cipher, logger)

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

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
