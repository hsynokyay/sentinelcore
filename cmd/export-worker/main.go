// cmd/export-worker — dedicated evidence-pack export daemon.
//
// Mirrors cmd/sla-worker / cmd/retention-worker: pgxpool, NATS JetStream
// (optional), signal-based shutdown. Configurable via env:
//
//	DATABASE_URL              (default: postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable)
//	NATS_URL                  (default: nats://localhost:4222)
//	EXPORT_WORKER_INTERVAL    (default: 30s — accepts time.ParseDuration syntax)
//	EXPORT_BLOB_DIR           (default: /var/lib/sentinelcore/exports)
//	EXPORT_BATCH_LIMIT        (default: 5 — jobs processed per cycle, max)
//
// The worker claims one queued job at a time using FOR UPDATE SKIP LOCKED so
// scaling out replicas is safe.
package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/export/evidence"
	"github.com/sentinelcore/sentinelcore/internal/governance/exportworker"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "export-worker").Logger()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := pgxpool.New(ctx, getEnv("DATABASE_URL", "postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable"))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	// NATS is optional — the worker doesn't currently publish events but
	// keeping the connection lets future state-change notifications drop in
	// without restarting the process.
	if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
		nc, js, nErr := sc_nats.Connect(sc_nats.Config{URL: natsURL})
		if nErr != nil {
			logger.Warn().Err(nErr).Msg("nats connect failed; continuing without")
		} else {
			defer nc.Close()
			if eErr := sc_nats.EnsureStreams(ctx, js); eErr != nil {
				logger.Warn().Err(eErr).Msg("ensure streams failed")
			}
		}
	}

	blobDir := getEnv("EXPORT_BLOB_DIR", "/var/lib/sentinelcore/exports")
	blob, err := evidence.NewFilesystemBlob(blobDir)
	if err != nil {
		logger.Fatal().Err(err).Str("dir", blobDir).Msg("create blob store")
	}
	logger.Info().Str("blob_dir", blobDir).Msg("blob store ready")

	interval := 30 * time.Second
	if v := os.Getenv("EXPORT_WORKER_INTERVAL"); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil && d > 0 {
			interval = d
		} else {
			logger.Warn().Str("EXPORT_WORKER_INTERVAL", v).Msg("invalid duration; falling back to 30s")
		}
	}

	batchLimit := 5
	if v := os.Getenv("EXPORT_BATCH_LIMIT"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 && n <= 100 {
			batchLimit = n
		}
	}

	logger.Info().
		Dur("interval", interval).
		Int("batch_limit", batchLimit).
		Msg("export worker started")

	w := exportworker.New(pool, blob)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// First cycle immediately so a freshly-deployed worker doesn't wait an
	// interval to pick up backlog jobs.
	runCycle(ctx, w, batchLimit, &logger)

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("export worker shutting down")
			return
		case <-ticker.C:
			runCycle(ctx, w, batchLimit, &logger)
		}
	}
}

// runCycle processes up to batchLimit jobs in this tick. Returns early when
// the queue is empty so the next tick doesn't busy-loop.
func runCycle(ctx context.Context, w *exportworker.Worker, batchLimit int, logger *zerolog.Logger) {
	for i := 0; i < batchLimit; i++ {
		res, err := w.RunOnce(ctx)
		if err != nil {
			logger.Error().Err(err).Msg("export worker cycle failed")
			return
		}
		if !res.Processed {
			return
		}
		logger.Info().
			Str("job_id", res.JobID.String()).
			Str("status", res.Status).
			Str("error", res.Error).
			Msg("export job processed")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
