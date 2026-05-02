package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/signal"
	"syscall"

	"github.com/redis/go-redis/v9"

	"github.com/sentinelcore/sentinelcore/internal/controlplane"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/db"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
	"github.com/sentinelcore/sentinelcore/pkg/ratelimit"
)

func main() {
	logger := observability.NewLogger("controlplane")

	// Graceful shutdown: context cancelled on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Database
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

	// Redis
	redisURL := envOrDefault("REDIS_URL", "redis://localhost:6379")
	redisOpts, err := redis.ParseURL(redisURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to parse Redis URL")
	}
	redisClient := redis.NewClient(redisOpts)
	defer redisClient.Close()
	logger.Info().Msg("connected to Redis")

	// NATS
	natsCfg := sc_nats.Config{
		URL: envOrDefault("NATS_URL", "nats://localhost:4222"),
	}
	nc, js, err := sc_nats.Connect(natsCfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to NATS")
	}
	defer nc.Close()
	logger.Info().Msg("connected to NATS")

	// Ensure streams
	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure NATS streams")
	}

	// JWT Manager
	jwtMgr, err := loadOrGenerateJWTManager()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create JWT manager")
	}
	logger.Info().Msg("JWT manager initialized")

	// Session store
	sessions := auth.NewSessionStoreFromClient(redisClient)

	// Audit emitter
	emitter := audit.NewEmitter(js)

	// Rate limiter
	limiter := ratelimit.NewLimiter(redisClient)

	// Server config
	serverCfg := controlplane.ServerConfig{
		Port:        envOrDefault("PORT", "8080"),
		MetricsPort: envOrDefault("METRICS_PORT", "9090"),
	}

	server := controlplane.NewServer(serverCfg, logger, pool, jwtMgr, sessions, emitter, limiter, js, nc, redisClient)

	logger.Info().Str("port", serverCfg.Port).Msg("starting control plane server")
	if err := server.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("server failed")
	}
}

func loadOrGenerateJWTManager() (*auth.JWTManager, error) {
	privKeyPath := os.Getenv("JWT_PRIVATE_KEY_FILE")
	pubKeyPath := os.Getenv("JWT_PUBLIC_KEY_FILE")

	if privKeyPath != "" && pubKeyPath != "" {
		privPEM, err := os.ReadFile(privKeyPath)
		if err != nil {
			return nil, err
		}
		pubPEM, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return nil, err
		}
		return auth.NewJWTManager(privPEM, pubPEM)
	}

	// Generate dev key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return auth.NewJWTManager(privPEM, pubPEM)
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
