package main

import (
	"context"
	"net/http"
	"os"

	"github.com/sentinelcore/sentinelcore/internal/vuln"
	"github.com/sentinelcore/sentinelcore/pkg/db"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("vuln-intel")
	ctx := context.Background()

	dbCfg := db.Config{
		Host:     envOrDefault("DB_HOST", "localhost"),
		Port:     envIntOrDefault("DB_PORT", 5432),
		Database: envOrDefault("DB_NAME", "sentinelcore"),
		User:     envOrDefault("DB_USER", "sentinelcore"),
		Password: envOrDefault("DB_PASSWORD", "dev-password"),
		MaxConns: envIntOrDefault("DB_MAX_CONNS", 20),
	}

	pool, err := db.NewPool(ctx, dbCfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()
	logger.Info().Msg("connected to PostgreSQL")

	svc := vuln.NewService(pool, logger)

	mux := http.NewServeMux()
	svc.RegisterRoutes(mux)

	port := envOrDefault("PORT", "9003")
	logger.Info().Str("port", port).Msg("starting vuln-intel service")
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		logger.Fatal().Err(err).Msg("server failed")
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			return def
		}
	}
	return n
}
