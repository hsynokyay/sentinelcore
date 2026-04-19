package auth

import (
	"context"
	"slices"
)

// Principal is the authenticated identity behind a request. Exactly one
// Principal exists per authenticated request; handlers read it via
// PrincipalFromContext.
//
// Kind is either "user" (JWT-authenticated) or "api_key" (sc_... token).
// Users resolve permissions through Role → RBAC cache; API keys carry
// their own Scopes list.
type Principal struct {
	Kind   string   // "user" | "api_key"
	OrgID  string
	UserID string   // empty for tenant-owned service accounts
	Role   string   // empty for api_key
	Scopes []string // empty for user
	KeyID  string   // empty for user
	JTI    string   // empty for api_key
}

// PermissionChecker abstracts the RBAC cache so middleware/tests can
// inject a fake without pulling the pgxpool dependency.
type PermissionChecker interface {
	Can(role, perm string) bool
}

// Can returns true iff this principal is allowed to perform the given
// permission. For users, delegates to the RBAC cache. For API keys,
// checks the embedded scopes list.
func (p Principal) Can(perm string, cache PermissionChecker) bool {
	switch p.Kind {
	case "user":
		if cache == nil {
			return false
		}
		return cache.Can(p.Role, perm)
	case "api_key":
		return slices.Contains(p.Scopes, perm)
	default:
		return false
	}
}

type principalKey struct{}

// WithPrincipal returns a child context carrying the principal.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext extracts the principal, if any.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
