package api

import (
	"encoding/json"
	"net/http"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// PermissionResolver is the subset of policy.Cache needed by MeHandler.
type PermissionResolver interface {
	PermissionsFor(role string) []string
}

// MeHandler serves GET /api/v1/auth/me — returns the caller's identity
// and current permission set. Permissions are always computed live from
// the RBAC cache; they are NOT embedded in the JWT.
type MeHandler struct {
	Cache PermissionResolver
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHENTICATED")
		return
	}

	user := map[string]string{
		"id":     p.UserID,
		"org_id": p.OrgID,
		"role":   p.Role,
	}
	var perms []string
	switch p.Kind {
	case "user":
		perms = h.Cache.PermissionsFor(p.Role)
	case "api_key":
		perms = p.Scopes
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user":        user,
		"permissions": perms,
	})
}
