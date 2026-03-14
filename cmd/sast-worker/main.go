package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sentinelcore/sentinelcore/internal/sast"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("sast-worker")
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

	// Load rules
	rulesPath := getEnv("RULES_PATH", "rules/builtin/sast-patterns.json")
	rules, err := sast.LoadRules(rulesPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to load rules")
	}
	logger.Info().Int("rules", len(rules)).Msg("rules loaded")

	// Signing key
	signingKey := []byte(getEnv("MSG_SIGNING_KEY", "dev-signing-key-change-me"))

	// Start worker
	analyzer := sast.NewAnalyzer(rules)
	worker := sast.NewWorker(js, analyzer, signingKey, logger)

	logger.Info().Msg("SAST worker starting")
	if err := worker.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("worker failed")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
