package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/apikeys"
)

type createAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresIn string   `json:"expires_in,omitempty"` // e.g. "30d", "90d", "365d"
}

// CreateAPIKey creates a new API key. The plaintext is returned once.
// POST /api/v1/api-keys
func (h *Handlers) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "system.config") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var req createAPIKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required", "BAD_REQUEST")
		return
	}

	// Default scopes: read-only findings + scans.
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"findings.read", "scans.read"}
	}

	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		d, err := parseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_in format (use 30d, 90d, 365d)", "BAD_REQUEST")
			return
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	result, err := apikeys.Create(r.Context(), h.pool, user.OrgID, user.UserID, req.Name, scopes, expiresAt)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to create API key")
		writeError(w, http.StatusInternalServerError, "failed to create API key", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "apikey.create", "user", user.UserID, "api_key", result.Key.ID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, result)
}

// ListAPIKeys lists all API keys for the org.
// GET /api/v1/api-keys
func (h *Handlers) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "system.config") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	keys, err := apikeys.List(r.Context(), h.pool, user.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
}

// RevokeAPIKey revokes an API key.
// DELETE /api/v1/api-keys/{id}
func (h *Handlers) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "system.config") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	keyID := r.PathValue("id")
	if err := apikeys.Revoke(r.Context(), h.pool, keyID, user.OrgID); err != nil {
		writeError(w, http.StatusNotFound, "API key not found", "NOT_FOUND")
		return
	}

	h.emitAuditEvent(r.Context(), "apikey.revoke", "user", user.UserID, "api_key", keyID, r.RemoteAddr, "success")
	w.WriteHeader(http.StatusNoContent)
}

func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, nil
	}
	unit := s[len(s)-1]
	val := s[:len(s)-1]
	var n int
	for _, c := range val {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	switch unit {
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported unit: %c", unit)
	}
}
