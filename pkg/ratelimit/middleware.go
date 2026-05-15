package ratelimit

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// TierConfig defines rate limit tiers for different endpoint categories.
//
// Phase 8 §4.1 A2: split reads from writes on the default path so a
// crawler or a mis-loop client can't exhaust the mutation budget.
// Reads default to 300/min, writes to 60/min; login stays the
// strictest at 10/min per IP.
type TierConfig struct {
	ReadLimit     int           // 300/min for GET/HEAD on general endpoints
	ReadWindow    time.Duration
	WriteLimit    int           // 60/min for POST/PATCH/PUT/DELETE on general endpoints
	WriteWindow   time.Duration
	DefaultLimit  int           // back-compat fallback (used when method is unknown)
	DefaultWindow time.Duration
	LoginLimit    int           // 10/min per IP for login (keep tight to slow credential stuffing)
	LoginWindow   time.Duration
	ScanLimit     int           // 20/min per user for scan creation
	ScanWindow    time.Duration
	UploadLimit   int           // 5/min per user for file uploads
	UploadWindow  time.Duration
}

// DefaultTierConfig returns production-safe rate limit tiers. Every
// limit + window has an env override so pilot/demo environments can
// relax without a code change.
func DefaultTierConfig() TierConfig {
	return TierConfig{
		ReadLimit:     envInt("READ_RATE_LIMIT", 300),
		ReadWindow:    envDuration("READ_RATE_WINDOW", time.Minute),
		WriteLimit:    envInt("WRITE_RATE_LIMIT", 60),
		WriteWindow:   envDuration("WRITE_RATE_WINDOW", time.Minute),
		DefaultLimit:  envInt("DEFAULT_RATE_LIMIT", 100),
		DefaultWindow: envDuration("DEFAULT_RATE_WINDOW", time.Minute),
		LoginLimit:    envInt("LOGIN_RATE_LIMIT", 60),
		LoginWindow:   envDuration("LOGIN_RATE_WINDOW", time.Minute),
		ScanLimit:     envInt("SCAN_RATE_LIMIT", 20),
		ScanWindow:    envDuration("SCAN_RATE_WINDOW", time.Minute),
		UploadLimit:   envInt("UPLOAD_RATE_LIMIT", 5),
		UploadWindow:  envDuration("UPLOAD_RATE_WINDOW", time.Minute),
	}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
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

	// Default: split reads from writes. Phase 8 §4.1 A2.
	limit, window = cfg.DefaultLimit, cfg.DefaultWindow
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		if cfg.ReadLimit > 0 {
			limit, window = cfg.ReadLimit, cfg.ReadWindow
		}
	case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		if cfg.WriteLimit > 0 {
			limit, window = cfg.WriteLimit, cfg.WriteWindow
		}
	}

	if user := auth.GetUser(r.Context()); user != nil {
		return "user:" + user.UserID, limit, window
	}
	return "ip:" + stripPort(r.RemoteAddr), limit, window
}

func stripPort(addr string) string {
	if i := strings.LastIndex(addr, ":"); i != -1 {
		return addr[:i]
	}
	return addr
}
