package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/pkg/apikeys"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// RotateAPIKey rotates the api_key identified by path parameter {id}.
// The response body contains the new plaintext (shown ONCE).
// The old plaintext stops working the instant the UPDATE commits.
func (h *Handlers) RotateAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHENTICATED")
		return
	}

	keyID := r.PathValue("id")
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "missing key id", "BAD_REQUEST")
		return
	}

	// Single atomic call — Rotate captures old prefix via CTE in the
	// same statement as the UPDATE. No TOCTOU window.
	result, err := apikeys.Rotate(r.Context(), h.pool, keyID, principal.OrgID)
	if err != nil {
		// Discriminate: no-rows → 404 (tenant isolation, revoked, or nonexistent).
		// Anything else → 500 (DB error, serialization failure).
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "key not found or revoked", "NOT_FOUND")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL")
		return
	}

	if h.audit != nil {
		_ = h.audit.Emit(r.Context(), audit.AuditEvent{
			ActorType:    principal.Kind,
			ActorID:      principal.UserID,
			Action:       "api_key.rotate",
			ResourceType: "api_key",
			ResourceID:   keyID,
			OrgID:        principal.OrgID,
			Result:       "success",
			Details: map[string]any{
				"old_prefix": result.OldPrefix,
				"new_prefix": result.Prefix,
			},
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result.CreateResult) // omit OldPrefix from response body
}
