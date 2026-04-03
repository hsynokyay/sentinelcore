package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

// HealthHandler returns an HTTP handler that responds with a simple liveness check.
// Use for Kubernetes livenessProbe: always returns 200 if the process is running.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// ReadinessDeps holds the dependencies checked by the readiness probe.
type ReadinessDeps struct {
	DB    *pgxpool.Pool
	Redis *redis.Client
	NATS  *nats.Conn
}

// ReadinessHandler returns an HTTP handler that checks all dependencies.
// Use for Kubernetes readinessProbe: returns 200 if all healthy, 503 if any unhealthy.
// Each dependency check has a 3-second timeout.
func ReadinessHandler(deps ReadinessDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		components := make(map[string]string)
		allHealthy := true

		// Check PostgreSQL (3s timeout)
		dbCtx, dbCancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer dbCancel()
		if deps.DB != nil {
			if err := deps.DB.Ping(dbCtx); err != nil {
				components["db"] = "error: " + err.Error()
				allHealthy = false
			} else {
				components["db"] = "ok"
			}
		} else {
			components["db"] = "not configured"
		}

		// Check Redis (3s timeout)
		redisCtx, redisCancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer redisCancel()
		if deps.Redis != nil {
			if err := deps.Redis.Ping(redisCtx).Err(); err != nil {
				components["redis"] = "error: " + err.Error()
				allHealthy = false
			} else {
				components["redis"] = "ok"
			}
		} else {
			components["redis"] = "not configured"
		}

		// Check NATS (no timeout needed — connection status is local)
		if deps.NATS != nil {
			if deps.NATS.IsConnected() {
				components["nats"] = "ok"
			} else {
				components["nats"] = "disconnected"
				allHealthy = false
			}
		} else {
			components["nats"] = "not configured"
		}

		status := "healthy"
		httpStatus := http.StatusOK
		if !allHealthy {
			status = "unhealthy"
			httpStatus = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)
		json.NewEncoder(w).Encode(map[string]any{
			"status":     status,
			"components": components,
		})
	}
}
