package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("policy-engine")

	// For Phase 1, Policy Engine runs as HTTP service.
	// DB connection needed for scope validation (optional at startup).
	svc := policy.NewService(nil) // DB pool will be passed when available

	mux := http.NewServeMux()
	mux.HandleFunc("/evaluate", svc.HandleEvaluate)
	mux.HandleFunc("/evaluate-scope", svc.HandleEvaluateScanScope)
	mux.HandleFunc("/healthz", observability.HealthHandler())

	port := os.Getenv("POLICY_ENGINE_PORT")
	if port == "" {
		port = "9006"
	}

	logger.Info().Str("port", port).Msg("Policy Engine starting")
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), mux); err != nil {
		logger.Fatal().Err(err).Msg("server failed")
	}
}
