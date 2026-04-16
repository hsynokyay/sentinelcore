package audit

import (
	"context"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// AuthzDenier implements auth.AuditDenier by emitting an AuditEvent
// for every permission denial.
type AuthzDenier struct {
	e *Emitter
}

// NewAuthzDenier wraps an existing Emitter.
func NewAuthzDenier(e *Emitter) *AuthzDenier {
	return &AuthzDenier{e: e}
}

// EmitAuthzDenied implements auth.AuditDenier.
func (d *AuthzDenier) EmitAuthzDenied(ctx context.Context, p auth.Principal, required string) {
	_ = d.e.Emit(ctx, AuditEvent{
		ActorType:    p.Kind,
		ActorID:      p.UserID, // empty for tenant-owned service-account keys
		Action:       "authz.denied",
		ResourceType: "permission",
		ResourceID:   required,
		OrgID:        p.OrgID,
		Result:       "failure",
		Details: map[string]any{
			"required":  required,
			"key_id":    p.KeyID,
			"role":      p.Role,
			"scopes":    p.Scopes,
		},
	})
}
