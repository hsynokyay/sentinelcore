package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/governance"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "retention-worker").Logger()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to PostgreSQL
	pool, err := pgxpool.New(ctx, getEnv("DATABASE_URL", "postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable"))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	// Connect to NATS
	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: getEnv("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to NATS")
	}
	defer nc.Close()

	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure NATS streams")
	}

	// Parse retention cycle interval
	intervalStr := getEnv("RETENTION_INTERVAL", "3600")
	intervalSec, _ := strconv.Atoi(intervalStr)
	if intervalSec <= 0 {
		intervalSec = 3600
	}

	logger.Info().Int("interval_seconds", intervalSec).Msg("retention worker started")

	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	// Run first cycle immediately
	runCycle(ctx, pool, js, &logger)

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("retention worker shutting down")
			return
		case <-ticker.C:
			runCycle(ctx, pool, js, &logger)
		}
	}
}

func runCycle(ctx context.Context, pool *pgxpool.Pool, js jetstream.JetStream, logger *zerolog.Logger) {
	now := time.Now()

	// Step 1: Expire stale approvals
	expired, err := governance.ExpirePendingApprovals(ctx, pool)
	if err != nil {
		logger.Error().Err(err).Msg("failed to expire pending approvals")
	} else {
		logger.Info().Int("count", expired).Msg("expired pending approvals")
	}

	// Step 2: Transition active -> archived
	archived, err := governance.TransitionToArchived(ctx, pool, now)
	if err != nil {
		logger.Error().Err(err).Msg("failed to transition to archived")
	} else {
		logger.Info().Int("count", archived).Msg("transitioned to archived")
	}

	// Step 3: Transition archived -> purge_pending
	purgePending, err := governance.TransitionToPurgePending(ctx, pool, now)
	if err != nil {
		logger.Error().Err(err).Msg("failed to transition to purge pending")
	} else {
		logger.Info().Int("count", purgePending).Msg("transitioned to purge pending")
	}

	// Step 4: Purge eligible records (skips legal hold)
	purged, err := governance.PurgeRecords(ctx, pool, now)
	if err != nil {
		logger.Error().Err(err).Msg("failed to purge records")
	} else {
		logger.Info().Int("count", purged).Msg("purged records")
	}

	// Step 5: Check SLA violations and publish events
	violations, err := governance.CheckSLAViolations(ctx, pool, now)
	if err != nil {
		logger.Error().Err(err).Msg("failed to check SLA violations")
		return
	}
	logger.Info().Int("count", len(violations)).Msg("detected SLA violations")

	// Record each violation and publish NATS event
	for i := range violations {
		v := &violations[i]
		if recErr := governance.RecordSLAViolation(ctx, pool, v); recErr != nil {
			logger.Error().Err(recErr).Str("finding_id", v.FindingID).Msg("failed to record SLA violation")
			continue
		}

		event := map[string]interface{}{
			"event_type":  "sla_violated",
			"finding_id":  v.FindingID,
			"org_id":      v.OrgID,
			"severity":    v.Severity,
			"deadline_at": v.DeadlineAt,
			"violated_at": v.ViolatedAt,
		}
		data, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			logger.Error().Err(marshalErr).Msg("failed to marshal SLA violation event")
			continue
		}

		if _, pubErr := js.Publish(ctx, "governance.notifications", data); pubErr != nil {
			logger.Error().Err(pubErr).Str("finding_id", v.FindingID).Msg("failed to publish SLA violation event")
		}
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
