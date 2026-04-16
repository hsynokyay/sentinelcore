package auth

import (
	"context"
	"encoding/json"
	"net/http"
)

// AuditDenier is invoked when a request is denied by RequirePermission.
// Kept as an interface so tests can inject a fake without pulling the
// pkg/audit NATS dependency.
type AuditDenier interface {
	EmitAuthzDenied(ctx context.Context, p Principal, required string)
}

// RequirePermission wraps an http.Handler, enforcing that the request's
// Principal has the named permission. On deny it returns 403 FORBIDDEN
// (or INSUFFICIENT_SCOPE for API keys) and emits an audit event.
//
// If no Principal is in the context, returns 401 UNAUTHENTICATED. This
// should not normally happen because AuthenticateMiddleware runs first,
// but the check keeps RequirePermission safe to compose in any order.
func RequirePermission(required string, checker PermissionChecker, denier AuditDenier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok {
				writeErr(w, http.StatusUnauthorized, "authentication required", "UNAUTHENTICATED")
				return
			}
			if p.Can(required, checker) {
				next.ServeHTTP(w, r)
				return
			}
			if denier != nil {
				denier.EmitAuthzDenied(r.Context(), p, required)
			}
			if p.Kind == "api_key" {
				writeErr(w, http.StatusForbidden, "missing scope: "+required, "INSUFFICIENT_SCOPE")
				return
			}
			writeErr(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		})
	}
}

func writeErr(w http.ResponseWriter, status int, msg, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
		"code":  code,
	})
}
