package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// TierConfig defines rate limit tiers for different endpoint categories.
type TierConfig struct {
	DefaultLimit int           // 100/min for general endpoints
	DefaultWindow time.Duration
	LoginLimit   int           // 10/min per IP for login
	LoginWindow  time.Duration
	ScanLimit    int           // 20/min per user for scan creation
	ScanWindow   time.Duration
	UploadLimit  int           // 5/min per user for file uploads
	UploadWindow time.Duration
}

// DefaultTierConfig returns production-safe rate limit tiers.
func DefaultTierConfig() TierConfig {
	return TierConfig{
		DefaultLimit:  100, DefaultWindow: time.Minute,
		LoginLimit:    10,  LoginWindow:   time.Minute,
		ScanLimit:     20,  ScanWindow:    time.Minute,
		UploadLimit:   5,   UploadWindow:  time.Minute,
	}
}

// HTTPMiddleware returns HTTP middleware that enforces per-user rate limits
// with endpoint-level tiers for sensitive operations.
func HTTPMiddleware(limiter *Limiter, cfg TierConfig, logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, limit, window := resolveRateLimit(r, cfg)

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

				logger.Warn().
					Str("key", key).
					Str("path", r.URL.Path).
					Str("method", r.Method).
					Int("limit", limit).
					Msg("rate limit exceeded")

				http.Error(w, `{"error":"rate limit exceeded","code":"RATE_LIMITED"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// resolveRateLimit determines the rate limit key, limit, and window based on
// the request path and authentication state.
func resolveRateLimit(r *http.Request, cfg TierConfig) (key string, limit int, window time.Duration) {
	path := r.URL.Path

	// Login endpoint: keyed by IP, stricter limit.
	if path == "/api/v1/auth/login" && r.Method == http.MethodPost {
		return "login:ip:" + stripPort(r.RemoteAddr), cfg.LoginLimit, cfg.LoginWindow
	}

	// Scan creation: keyed by user, moderate limit.
	if strings.HasSuffix(path, "/scans") && r.Method == http.MethodPost {
		if user := auth.GetUser(r.Context()); user != nil {
			return "scan:user:" + user.UserID, cfg.ScanLimit, cfg.ScanWindow
		}
		return "scan:ip:" + stripPort(r.RemoteAddr), cfg.ScanLimit, cfg.ScanWindow
	}

	// Upload: keyed by user, strict limit.
	if strings.HasSuffix(path, "/artifacts") && r.Method == http.MethodPost {
		if user := auth.GetUser(r.Context()); user != nil {
			return "upload:user:" + user.UserID, cfg.UploadLimit, cfg.UploadWindow
		}
		return "upload:ip:" + stripPort(r.RemoteAddr), cfg.UploadLimit, cfg.UploadWindow
	}

	// Default: keyed by user or IP.
	if user := auth.GetUser(r.Context()); user != nil {
		return "user:" + user.UserID, cfg.DefaultLimit, cfg.DefaultWindow
	}
	return "ip:" + stripPort(r.RemoteAddr), cfg.DefaultLimit, cfg.DefaultWindow
}

func stripPort(addr string) string {
	if i := strings.LastIndex(addr, ":"); i != -1 {
		return addr[:i]
	}
	return addr
}
