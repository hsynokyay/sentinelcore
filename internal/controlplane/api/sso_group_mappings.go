package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/sso"
)

type groupMappingJSON struct {
	ID       string `json:"id,omitempty"`
	Group    string `json:"group_claim"`
	Role     string `json:"role_id"`
	Priority int    `json:"priority"`
}

func toMappingJSON(m sso.StoredMapping) groupMappingJSON {
	return groupMappingJSON{
		ID:       m.ID,
		Group:    m.Group,
		Role:     m.Role,
		Priority: m.Priority,
	}
}

// ListSSOMappings handles GET /api/v1/sso/providers/{id}/mappings — sso.manage.
func (h *Handlers) ListSSOMappings(w http.ResponseWriter, r *http.Request) {
	if h.ssoMappings == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	providerID := r.PathValue("id")
	list, err := h.ssoMappings.List(r.Context(), providerID)
	if err != nil {
		h.logger.Error().Err(err).Str("provider_id", providerID).Msg("list sso mappings")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	out := make([]groupMappingJSON, 0, len(list))
	for _, m := range list {
		out = append(out, toMappingJSON(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"mappings": out})
}

// CreateSSOMapping handles POST /api/v1/sso/providers/{id}/mappings — sso.manage.
// Upsert semantics: repeating (provider_id, group) rotates the role/priority.
func (h *Handlers) CreateSSOMapping(w http.ResponseWriter, r *http.Request) {
	if h.ssoMappings == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	providerID := r.PathValue("id")

	var req groupMappingJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", "BAD_REQUEST")
		return
	}
	defer r.Body.Close()

	if req.Group == "" || len(req.Group) > 256 {
		writeError(w, http.StatusBadRequest, "group_claim must be 1-256 chars", "BAD_REQUEST")
		return
	}
	if req.Role == "" {
		writeError(w, http.StatusBadRequest, "role_id is required", "BAD_REQUEST")
		return
	}
	if req.Priority < 1 || req.Priority > 10000 {
		writeError(w, http.StatusBadRequest, "priority must be 1-10000", "BAD_REQUEST")
		return
	}

	id, err := h.ssoMappings.Create(r.Context(), providerID, req.Group, req.Role, req.Priority)
	if err != nil {
		h.logger.Error().Err(err).Str("provider_id", providerID).Msg("create sso mapping")
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}

	h.emitAuditSSO(r.Context(), principal, "auth.sso.mapping.upsert", providerID, map[string]any{
		"mapping_id":  id,
		"group_claim": req.Group,
		"role_id":     req.Role,
		"priority":    req.Priority,
	})

	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// DeleteSSOMapping handles
// DELETE /api/v1/sso/providers/{id}/mappings/{mapping_id} — sso.manage.
func (h *Handlers) DeleteSSOMapping(w http.ResponseWriter, r *http.Request) {
	if h.ssoMappings == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	providerID := r.PathValue("id")
	mappingID := r.PathValue("mapping_id")

	if err := h.ssoMappings.Delete(r.Context(), providerID, mappingID); err != nil {
		if errors.Is(err, sso.ErrMappingNotFound) {
			writeError(w, http.StatusNotFound, "not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("delete sso mapping")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}

	h.emitAuditSSO(r.Context(), principal, "auth.sso.mapping.delete", providerID, map[string]any{
		"mapping_id": mappingID,
	})

	w.WriteHeader(http.StatusNoContent)
}
