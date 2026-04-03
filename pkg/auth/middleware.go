package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

// UserContextKey is the context key for storing user information.
const UserContextKey contextKey = "user"

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
			}

			userCtx := &UserContext{
				UserID: claims.Subject,
				OrgID:  claims.OrgID,
				Role:   claims.Role,
				JTI:    claims.ID,
			}

			ctx := context.WithValue(r.Context(), UserContextKey, userCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUser extracts the UserContext from the request context.
func GetUser(ctx context.Context) *UserContext {
	user, _ := ctx.Value(UserContextKey).(*UserContext)
	return user
}
