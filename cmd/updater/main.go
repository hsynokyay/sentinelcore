package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/sentinelcore/sentinelcore/internal/updater"
	"github.com/sentinelcore/sentinelcore/pkg/db"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("updater")

	ctx := context.Background()
	pool, err := db.NewPool(ctx, db.Config{
		Host:     envOr("DB_HOST", "localhost"),
		Port:     5432,
		Database: envOr("DB_NAME", "sentinelcore"),
		User:     envOr("DB_USER", "sentinelcore"),
		Password: envOr("DB_PASSWORD", "dev-password"),
		MaxConns: 10,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	trustDir := envOr("TRUST_DIR", "/etc/sentinelcore/trust")
	stageDir := envOr("STAGE_DIR", "/var/lib/sentinelcore/staging")

	trustStore := updater.NewTrustStore(trustDir, pool)
	lockdownMgr := updater.NewLockdownManager(pool)
	verifier := updater.NewVerifier(trustStore, lockdownMgr)
	svc := updater.NewService(verifier, lockdownMgr, trustStore, stageDir)

	mux := http.NewServeMux()
	mux.HandleFunc("/import", svc.HandleImport)
	mux.HandleFunc("/verify", svc.HandleVerify)
	mux.HandleFunc("/trust-status", svc.HandleTrustStatus)
	mux.HandleFunc("/lockdown/enable", svc.HandleLockdownEnable)
	mux.HandleFunc("/lockdown/disable", svc.HandleLockdownDisable)
	mux.HandleFunc("/healthz", observability.HealthHandler())

	port := envOr("UPDATER_PORT", "9009")
	logger.Info().Str("port", port).Msg("Update Manager starting")
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), mux); err != nil {
		logger.Fatal().Err(err).Msg("server failed")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
