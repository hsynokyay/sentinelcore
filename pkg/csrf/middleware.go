// Package csrf implements double-submit cookie CSRF protection.
//
// Two authentication modes are distinguished:
//
// Mode 1 (Cookie auth): sentinel_access_token cookie present → CSRF mandatory
// on POST/PUT/PATCH/DELETE. Validates X-CSRF-Token header matches sentinel_csrf
// cookie, and Origin/Referer matches allowed origins.
//
// Mode 2 (Bearer auth): Authorization: Bearer header present, no cookie → CSRF
// skipped. Preserves backward compatibility for API clients and CI/CD.
package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
)

const (
	// CookieName is the CSRF token cookie name. Non-httpOnly so JS can read it.
	CookieName = "sentinel_csrf"
	// HeaderName is the header the frontend sends the CSRF token in.
	HeaderName = "X-CSRF-Token"
	// TokenLength is the byte length of the CSRF token (32 bytes = 64 hex chars).
	TokenLength = 32
)

// Config holds CSRF middleware configuration.
type Config struct {
	AllowedOrigins []string // Origins to validate against (from CORS_ORIGIN)
	SecureCookie   func(r *http.Request) bool // Determines Secure flag
}

// Middleware returns HTTP middleware that enforces CSRF protection.
func Middleware(cfg Config, logger zerolog.Logger) func(http.Handler) http.Handler {
	allowedHosts := make(map[string]bool)
	for _, o := range cfg.AllowedOrigins {
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			allowedHosts[u.Host] = true
		}
	}

	csrfLog := logger.With().Str("component", "csrf").Logger()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Safe methods are exempt.
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Login is exempt (no session yet).
			if r.URL.Path == "/api/v1/auth/login" {
				next.ServeHTTP(w, r)
				return
			}

			// Determine authentication mode.
			_, hasCookie := getCookie(r, "sentinel_access_token")
			hasBearer := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")

			// Mode 2: Pure Bearer auth without cookies → skip CSRF.
			if hasBearer && !hasCookie {
				next.ServeHTTP(w, r)
				return
			}

			// Mode 1: Cookie auth → CSRF required.
			if !hasCookie {
				// No cookie and no bearer → auth middleware will reject.
				next.ServeHTTP(w, r)
				return
			}

			// Validate CSRF token.
			csrfCookie, hasCsrfCookie := getCookie(r, CookieName)
			csrfHeader := r.Header.Get(HeaderName)

			if !hasCsrfCookie || csrfCookie == "" {
				csrfLog.Warn().
					Str("path", r.URL.Path).
					Str("method", r.Method).
					Bool("has_cookie", hasCookie).
					Bool("has_bearer", hasBearer).
					Str("reason", "missing_csrf_cookie").
					Msg("CSRF rejection")
				writeCSRFError(w)
				return
			}

			if csrfHeader == "" {
				csrfLog.Warn().
					Str("path", r.URL.Path).
					Str("method", r.Method).
					Bool("has_cookie", hasCookie).
					Bool("has_bearer", hasBearer).
					Str("reason", "missing_csrf_header").
					Msg("CSRF rejection")
				writeCSRFError(w)
				return
			}

			if subtle.ConstantTimeCompare([]byte(csrfCookie), []byte(csrfHeader)) != 1 {
				csrfLog.Warn().
					Str("path", r.URL.Path).
					Str("method", r.Method).
					Bool("has_cookie", hasCookie).
					Bool("has_bearer", hasBearer).
					Str("reason", "token_mismatch").
					Msg("CSRF rejection")
				writeCSRFError(w)
				return
			}

			// Validate Origin / Referer.
			if len(allowedHosts) > 0 {
				if !validateOriginOrReferer(r, allowedHosts) {
					origin := r.Header.Get("Origin")
					referer := r.Header.Get("Referer")
					csrfLog.Warn().
						Str("path", r.URL.Path).
						Str("method", r.Method).
						Str("origin", origin).
						Str("referer_host", extractHost(referer)).
						Str("reason", "invalid_origin").
						Msg("CSRF rejection")
					writeCSRFError(w)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GenerateToken creates a cryptographically random CSRF token.
func GenerateToken() (string, error) {
	b := make([]byte, TokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validateOriginOrReferer checks that the request's Origin or Referer
// matches one of the allowed hosts.
func validateOriginOrReferer(r *http.Request, allowedHosts map[string]bool) bool {
	// Check Origin header first (sent by all modern browsers on mutations).
	origin := r.Header.Get("Origin")
	if origin != "" {
		if u, err := url.Parse(origin); err == nil && u.Host != "" {
			return allowedHosts[u.Host]
		}
		return false
	}

	// Fallback to Referer.
	referer := r.Header.Get("Referer")
	if referer != "" {
		if u, err := url.Parse(referer); err == nil && u.Host != "" {
			return allowedHosts[u.Host]
		}
		return false
	}

	// No Origin or Referer on a cookie-authenticated mutation → reject.
	return false
}

func getCookie(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func extractHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

func writeCSRFError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"csrf validation failed","code":"CSRF_FAILED"}`))
}
