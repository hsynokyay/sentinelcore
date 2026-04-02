package api

import (
	"net/http"

	"github.com/sentinelcore/sentinelcore/internal/governance"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

// GetRetentionPolicies returns the retention policies from org settings.
func (h *Handlers) GetRetentionPolicies(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "retention.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	settings, err := governance.GetOrgSettings(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get org settings for retention policies")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"retention_policies": settings.RetentionPolicies,
	})
}

// UpdateRetentionPolicies updates the retention policies in org settings.
func (h *Handlers) UpdateRetentionPolicies(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "retention.manage") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var req struct {
		RetentionPolicies map[string]governance.RetentionPolicy `json:"retention_policies"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	// Get current settings, update only the retention policies field
	settings, err := governance.GetOrgSettings(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get org settings for retention update")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	settings.RetentionPolicies = req.RetentionPolicies

	if err := governance.UpsertOrgSettings(r.Context(), h.pool, user.UserID, user.OrgID, settings); err != nil {
		h.logger.Error().Err(err).Msg("failed to update retention policies")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "retention.policies.updated", "user", user.UserID, "org_settings", user.OrgID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, map[string]any{
		"retention_policies": settings.RetentionPolicies,
	})
}

// ListRetentionRecords returns retention stats grouped by resource type and lifecycle.
func (h *Handlers) ListRetentionRecords(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "retention.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	stats, err := governance.GetRetentionStats(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list retention records")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"records": stats})
}

// GetRetentionStats returns retention record counts grouped by resource type and lifecycle.
func (h *Handlers) GetRetentionStats(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "retention.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	stats, err := governance.GetRetentionStats(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get retention stats")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"stats": stats})
}
