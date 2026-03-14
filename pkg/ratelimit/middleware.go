package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// HTTPMiddleware returns HTTP middleware that enforces rate limits.
// It uses the authenticated user ID if available, otherwise falls back to IP address.
func HTTPMiddleware(limiter *Limiter, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var key string
			if user := auth.GetUser(r.Context()); user != nil {
				key = "user:" + user.UserID
			} else {
				key = "ip:" + r.RemoteAddr
			}

			result, err := limiter.Allow(r.Context(), key, limit, window)
			if err != nil {
				http.Error(w, `{"error":"rate limit error"}`, http.StatusInternalServerError)
				return
			}

			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))

			if !result.Allowed {
				retryAfter := time.Until(result.ResetAt).Seconds()
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter))
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
