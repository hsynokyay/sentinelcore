package auth

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"
)

type contextKey string

// UserContextKey is the context key for storing user information.
const UserContextKey contextKey = "user"

// APIKeyResolved is the result of resolving an API key. Populated by the
// apikeys package and consumed by the auth middleware.
type APIKeyResolved struct {
	KeyID  string
	OrgID  string
	UserID string
	Role   string
	Scopes []string
}

// APIKeyResolverFunc resolves an API key plaintext to a resolved key, or
// returns nil if invalid/expired/revoked. Set via SetAPIKeyResolver.
type APIKeyResolverFunc func(ctx context.Context, plainKey string) (*APIKeyResolved, error)

var apiKeyResolver APIKeyResolverFunc

// SetAPIKeyResolver configures the global API key resolver. Called once at
// startup by the controlplane after the DB pool is available.
func SetAPIKeyResolver(fn APIKeyResolverFunc) {
	apiKeyResolver = fn
}

// APIKeyAuthCounterFunc is an optional callback to increment metrics.
var APIKeyAuthCounterFunc func(status string)

func apiKeyAuthCounter(status string) {
	if APIKeyAuthCounterFunc != nil {
		APIKeyAuthCounterFunc(status)
	}
}

// UserContext holds the authenticated user's information extracted from JWT.
type UserContext struct {
	UserID string
	OrgID  string
	Role   string
	JTI    string
}

// AuthMiddleware returns HTTP middleware that validates JWT tokens from the Authorization header
// and checks that the session has not been revoked.
func AuthMiddleware(jwtMgr *JWTManager, sessions *SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header or httpOnly cookie (fallback).
			token := ""
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
					token = parts[1]
				}
			}
			if token == "" {
				if cookie, err := r.Cookie("sentinel_access_token"); err == nil && cookie.Value != "" {
					token = cookie.Value
				}
			}
			if token == "" {
				http.Error(w, `{"error":"missing authorization"}`, http.StatusUnauthorized)
				return
			}

			// API key path: tokens starting with "sc_" are API keys,
			// resolved via hash lookup instead of JWT validation.
			if strings.HasPrefix(token, "sc_") && apiKeyResolver != nil {
				rk, rkErr := apiKeyResolver(r.Context(), token)
				if rkErr != nil || rk == nil {
					apiKeyAuthCounter("failed")
					http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
					return
				}
				apiKeyAuthCounter("success")
				userCtx := &UserContext{
					UserID: rk.UserID,
					OrgID:  rk.OrgID,
					Role:   rk.Role,
				}
				principal := Principal{
					Kind:   "api_key",
					OrgID:  rk.OrgID,
					UserID: rk.UserID,
					Role:   rk.Role,
					Scopes: rk.Scopes,
					KeyID:  rk.KeyID,
				}
				ctx := context.WithValue(r.Context(), UserContextKey, userCtx)
				ctx = WithPrincipal(ctx, principal)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			claims, err := jwtMgr.ValidateToken(token)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			if sessions != nil {
				active, err := sessions.IsActive(r.Context(), claims.ID)
				if err != nil || !active {
					http.Error(w, `{"error":"session revoked"}`, http.StatusUnauthorized)
					return
				}

				// Session idle timeout: reject sessions that have been idle too long.
				idleTimeout := parseIdleTimeout()
				if idleTimeout > 0 {
					idle, err := sessions.IsIdle(r.Context(), claims.ID, idleTimeout)
					if err == nil && idle {
						http.Error(w, `{"error":"session idle timeout","code":"SESSION_IDLE"}`, http.StatusUnauthorized)
						return
					}
				}

				// Phase 8 §5.2: absolute session lifetime. Unlike idle,
				// this timestamp NEVER advances on activity, so a user
				// kept-warm session still hits the ceiling. Default 12h;
				// override via SC_ABSOLUTE_SESSION_LIFETIME env (duration).
				absoluteLifetime := parseAbsoluteLifetime()
				if absoluteLifetime > 0 {
					expired, err := sessions.IsAbsoluteExpired(r.Context(), claims.ID, absoluteLifetime)
					if err == nil && expired {
						http.Error(w, `{"error":"session expired","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
						return
					}
				}

				// Touch session to track activity for idle timeout.
				_ = sessions.TouchSession(r.Context(), claims.ID, 15*time.Minute)
			}

			userCtx := &UserContext{
				UserID: claims.Subject,
				OrgID:  claims.OrgID,
				Role:   claims.Role,
				JTI:    claims.ID,
			}

			// Phase 1 Task 6.1: also store a Principal so RequirePermission middleware
			// can read it. UserContext is kept for backward compatibility with legacy
			// handlers; new code should prefer Principal via PrincipalFromContext.
			principal := Principal{
				Kind:   "user",
				OrgID:  claims.OrgID,
				UserID: claims.Subject,
				Role:   claims.Role, // already translated to new vocabulary by JWT.ValidateToken (Task 4.1)
				JTI:    claims.ID,
			}

			ctx := context.WithValue(r.Context(), UserContextKey, userCtx)
			ctx = WithPrincipal(ctx, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUser extracts the UserContext from the request context.
func GetUser(ctx context.Context) *UserContext {
	user, _ := ctx.Value(UserContextKey).(*UserContext)
	return user
}

// parseIdleTimeout reads SESSION_IDLE_TIMEOUT env var (default: 30m).
func parseIdleTimeout() time.Duration {
	v := os.Getenv("SESSION_IDLE_TIMEOUT")
	if v == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// parseAbsoluteLifetime reads SC_ABSOLUTE_SESSION_LIFETIME (default: 12h).
// Phase 8 §5.2 — ceiling on how long a single login can persist,
// independent of activity. 0 disables the check.
func parseAbsoluteLifetime() time.Duration {
	v := os.Getenv("SC_ABSOLUTE_SESSION_LIFETIME")
	if v == "" {
		return 12 * time.Hour
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 12 * time.Hour
	}
	return d
}
