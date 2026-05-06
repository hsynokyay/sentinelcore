package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/internal/governance"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

// SLADashboard returns aggregated SLA posture for the caller's org.
//
// GET /api/v1/governance/sla/dashboard?warn_days=7
func (h *Handlers) SLADashboard(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.sla.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}

	warnDays := 7
	if v := r.URL.Query().Get("warn_days"); v != "" {
		if n, parseErr := strconv.Atoi(v); parseErr == nil && n > 0 && n <= 30 {
			warnDays = n
		}
	}

	dash, err := governance.GetSLADashboard(r.Context(), h.pool, orgID, time.Duration(warnDays)*24*time.Hour)
	if err != nil {
		h.logger.Error().Err(err).Msg("sla dashboard")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, dash)
}

// ListSLAViolationsHandler returns recent SLA violations for the caller's org.
//
// GET /api/v1/governance/sla/violations?status=open&limit=100
func (h *Handlers) ListSLAViolationsHandler(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.sla.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	statusFilter := r.URL.Query().Get("status")
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, parseErr := strconv.Atoi(v); parseErr == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	out, err := governance.ListSLAViolations(r.Context(), h.pool, orgID, statusFilter, limit)
	if err != nil {
		h.logger.Error().Err(err).Msg("list sla violations")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"violations": out, "limit": limit})
}

// GetProjectSLAPolicyHandler returns the per-project SLA override.
//
// GET /api/v1/governance/sla/policies/{project_id}
//
// Returns 404 when no override exists; the caller can fall back to
// org-level defaults from /governance/settings.
func (h *Handlers) GetProjectSLAPolicyHandler(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.sla.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	pidStr := r.PathValue("project_id")
	projectID, err := uuid.Parse(pidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "project_id must be a uuid", "BAD_REQUEST")
		return
	}
	pol, err := governance.GetProjectSLAPolicy(r.Context(), h.pool, projectID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "no project SLA policy", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("get project sla policy")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

// PutProjectSLAPolicyHandler creates or updates the per-project SLA override.
//
// PUT /api/v1/governance/sla/policies/{project_id}
// Body: { "sla_days": {"critical":1,"high":3,"medium":14,"low":60} }
func (h *Handlers) PutProjectSLAPolicyHandler(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.sla.write") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	updatedBy, err := uuid.Parse(user.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id on session", "BAD_REQUEST")
		return
	}
	pidStr := r.PathValue("project_id")
	projectID, err := uuid.Parse(pidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "project_id must be a uuid", "BAD_REQUEST")
		return
	}

	var body struct {
		SLADays map[string]int `json:"sla_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if body.SLADays == nil {
		writeError(w, http.StatusBadRequest, "sla_days is required", "BAD_REQUEST")
		return
	}

	pol, err := governance.UpsertProjectSLAPolicy(r.Context(), h.pool, orgID, projectID, updatedBy, body.SLADays)
	if err != nil {
		// Validation errors come back as plain errors — return 400.
		h.logger.Warn().Err(err).Msg("upsert project sla policy")
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}

	h.emitAuditEvent(r.Context(), "governance.sla.policy.updated", "user", user.UserID, "project", pidStr, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, pol)
}

// DeleteProjectSLAPolicyHandler removes the per-project SLA override (so the
// project falls back to org-level defaults). Idempotent: 204 on success and
// 404 only when caller asked for a row that does not exist.
//
// DELETE /api/v1/governance/sla/policies/{project_id}
func (h *Handlers) DeleteProjectSLAPolicyHandler(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.sla.write") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	pidStr := r.PathValue("project_id")
	projectID, err := uuid.Parse(pidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "project_id must be a uuid", "BAD_REQUEST")
		return
	}
	err = governance.DeleteProjectSLAPolicy(r.Context(), h.pool, projectID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "no project SLA policy", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("delete project sla policy")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	h.emitAuditEvent(r.Context(), "governance.sla.policy.deleted", "user", user.UserID, "project", pidStr, r.RemoteAddr, "success")
	w.WriteHeader(http.StatusNoContent)
}
