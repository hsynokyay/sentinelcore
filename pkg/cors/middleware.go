// Package cors provides CORS middleware for the SentinelCore control plane.
package cors

import (
	"net/http"
	"strings"
)

// Config holds CORS configuration.
type Config struct {
	AllowedOrigins []string // Explicit origins (no wildcards when credentials are used)
}

// Middleware returns HTTP middleware that sets CORS headers.
// When credentials: "include" is used by the frontend, Access-Control-Allow-Origin
// must be an explicit origin (not *). This middleware validates the Origin header
// against the allowed list and reflects the matching origin.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[strings.TrimRight(o, "/")] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" && allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, X-Request-ID")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.Header().Set("Vary", "Origin")
			}

			// Handle preflight
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
