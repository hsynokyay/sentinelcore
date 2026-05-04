package authz

import (
	"net/http"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// RequireDASTRole returns middleware that allows the request only when the
// authenticated user has the named DAST role. Reads identity via auth.GetUser.
func RequireDASTRole(store RoleStore, role Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.GetUser(r.Context())
			if user == nil || user.UserID == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			has, err := store.HasRole(r.Context(), user.UserID, role)
			if err != nil {
				http.Error(w, "authz lookup failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if !has {
				http.Error(w, "forbidden: missing role "+string(role), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyDASTRole allows the request when the user has at least one of
// the named roles.
func RequireAnyDASTRole(store RoleStore, roles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.GetUser(r.Context())
			if user == nil || user.UserID == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			for _, role := range roles {
				has, err := store.HasRole(r.Context(), user.UserID, role)
				if err != nil {
					http.Error(w, "authz lookup failed: "+err.Error(), http.StatusInternalServerError)
					return
				}
				if has {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "forbidden: missing required DAST role", http.StatusForbidden)
		})
	}
}
