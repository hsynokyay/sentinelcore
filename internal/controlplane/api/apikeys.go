package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/apikeys"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// createAPIKeyRequest is the JSON body for POST /api/v1/api-keys.
type createAPIKeyRequest struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Scopes           []string `json:"scopes"`
	ExpiresIn        string   `json:"expires_in"`        // e.g. "90d", "30d", "1h"
	IsServiceAccount bool     `json:"is_service_account"`
}

// CreateAPIKey handles POST /api/v1/api-keys.
//
// Business rules:
//   - api_key callers are always rejected (keys cannot create keys).
//   - Service-account keys require the caller to have role owner or admin.
//   - Scopes are validated against the RBAC catalog and the creator's
//     own permission ceiling (ValidateScopes).
//   - Returns 201 with a CreateResult containing the one-time plaintext.
func (h *Handlers) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}

	// API keys cannot create other API keys.
	if p.Kind == "api_key" {
		writeError(w, http.StatusForbidden, "api_key principals cannot create api keys", "FORBIDDEN")
		return
	}

	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	defer r.Body.Close()

	// Service-account keys require owner or admin.
	if req.IsServiceAccount {
		if p.Role != "owner" && p.Role != "admin" {
			writeError(w, http.StatusForbidden, "only owner or admin may create service-account keys", "FORBIDDEN")
			return
		}
	}

	// Build the creator's permission set.
	var creatorPerms map[string]struct{}
	if p.Kind == "user" {
		perms := h.rbacCache.PermissionsFor(p.Role)
		creatorPerms = make(map[string]struct{}, len(perms))
		for _, perm := range perms {
			creatorPerms[perm] = struct{}{}
		}
	} else {
		// api_key branch is already rejected above; this is a safety fallback.
		creatorPerms = make(map[string]struct{}, len(p.Scopes))
		for _, s := range p.Scopes {
			creatorPerms[s] = struct{}{}
		}
	}

	// Build the known-permissions set from the RBAC catalog.
	allPerms := h.rbacCache.AllPermissions()
	knownPerms := make(map[string]struct{}, len(allPerms))
	for _, perm := range allPerms {
		knownPerms[perm] = struct{}{}
	}

	// Resolve expiry.
	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		d, err := parseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_in: "+err.Error(), "BAD_REQUEST")
			return
		}
		t := time.Now().UTC().Add(d)
		expiresAt = &t
	}

	in := apikeys.CreateInput{
		OrgID:              p.OrgID,
		CreatedBy:          p.UserID,
		UserID:             p.UserID,
		Name:               req.Name,
		Description:        req.Description,
		Scopes:             req.Scopes,
		ExpiresAt:          expiresAt,
		IsServiceAccount:   req.IsServiceAccount,
		CreatorPermissions: creatorPerms,
		KnownPermissions:   knownPerms,
	}
	if req.IsServiceAccount {
		in.UserID = "" // service accounts have no user_id
	}

	result, err := apikeys.Create(r.Context(), h.pool, in)
	if err != nil {
		switch {
		case errors.Is(err, apikeys.EmptyScopesError):
			writeError(w, http.StatusBadRequest, err.Error(), "EMPTY_SCOPES")
		default:
			var dupErr *apikeys.DuplicateScopeError
			var unknownErr *apikeys.UnknownScopeError
			var escalErr *apikeys.PrivilegeEscalationError
			switch {
			case errors.As(err, &dupErr):
				writeError(w, http.StatusBadRequest, err.Error(), "DUPLICATE_SCOPE")
			case errors.As(err, &unknownErr):
				writeError(w, http.StatusBadRequest, err.Error(), "UNKNOWN_SCOPE")
			case errors.As(err, &escalErr):
				writeError(w, http.StatusForbidden, err.Error(), "PRIVILEGE_ESCALATION")
			default:
				h.logger.Error().Err(err).Msg("CreateAPIKey: create failed")
				writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
			}
		}
		return
	}

	// Emit audit event (best-effort; nil emitter is safe to skip).
	// Details capture the operational metadata forensic reviewers need
	// (scopes granted, service-account flag, expiry). Plaintext is NEVER
	// included — it was only in result.PlainText, which isn't referenced here.
	if h.audit != nil {
		_ = h.audit.Emit(r.Context(), audit.AuditEvent{
			ActorType:    p.Kind,
			ActorID:      p.UserID,
			Action:       "api_key.create",
			ResourceType: "api_key",
			ResourceID:   result.ID,
			OrgID:        p.OrgID,
			Result:       "success",
			Details: map[string]any{
				"scopes":             result.Scopes,
				"is_service_account": result.IsServiceAccount,
				"expires_at":         result.ExpiresAt,
			},
		})
	}

	writeJSON(w, http.StatusCreated, result)
}

// ListAPIKeys lists all API keys for the caller's org.
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

// parseDuration accepts "90d", "30d", "1h", "15m", or any time.ParseDuration input.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
