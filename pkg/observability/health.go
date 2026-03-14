package observability

import (
	"encoding/json"
	"net/http"
)

// HealthHandler returns an HTTP handler that responds with a health status.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}
