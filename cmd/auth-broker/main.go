// Command auth-broker runs the SentinelCore Auth Session Broker.
// It manages authenticated sessions for DAST scanning, supporting
// multiple auth strategies (bearer, OAuth2 CC, form login, API key).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/internal/authbroker"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "auth-broker").Logger()

	broker := authbroker.NewBroker(logger)
	_ = broker

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info().Str("signal", sig.String()).Msg("shutting down")
		cancel()
	}()

	logger.Info().Msg("Auth Session Broker started")
	<-ctx.Done()
	logger.Info().Msg("Auth Session Broker stopped")
}
