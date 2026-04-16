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
			// NOTE: When Phase 2 (API key scopes) lands, this middleware will also
			// route `Bearer sc_...` tokens through apikeys.Resolve and populate a
			// Principal with Kind=="api_key", Scopes=[...], KeyID=... — that code
			// path does not exist yet in Phase 1.

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			claims, err := jwtMgr.ValidateToken(parts[1])
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
