package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/governance"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

// GetGovernanceSettings returns the governance settings for the authenticated user's org.
func (h *Handlers) GetGovernanceSettings(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.settings.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	settings, err := governance.GetOrgSettings(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get governance settings")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, settings)
}

// UpdateGovernanceSettings updates the governance settings for the authenticated user's org.
func (h *Handlers) UpdateGovernanceSettings(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.settings.write") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var settings governance.OrgSettings
	if err := decodeJSON(r, &settings); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	if err := governance.UpsertOrgSettings(r.Context(), h.pool, user.UserID, user.OrgID, &settings); err != nil {
		h.logger.Error().Err(err).Msg("failed to update governance settings")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "governance.settings.update", "user", user.UserID, "org_settings", user.OrgID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// ListApprovals returns paged approval requests, optionally filtered by status.
func (h *Handlers) ListApprovals(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.approvals.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	status := r.URL.Query().Get("status")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50
	offset := 0
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 200 {
			limit = v
		}
	}
	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
			offset = v
		}
	}

	approvals, err := governance.ListApprovalRequests(r.Context(), h.pool, user.UserID, user.OrgID, status, limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list approvals")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if approvals == nil {
		approvals = []governance.ApprovalRequest{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"approvals": approvals,
		"limit":     limit,
		"offset":    offset,
	})
}

// GetApproval returns a single approval request by ID.
func (h *Handlers) GetApproval(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.approvals.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	approval, err := governance.GetApprovalRequest(r.Context(), h.pool, user.UserID, user.OrgID, id)
	if err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to get approval")
		writeError(w, http.StatusNotFound, "approval not found", "NOT_FOUND")
		return
	}

	writeJSON(w, http.StatusOK, approval)
}

// DecideApproval approves or rejects a pending approval request.
func (h *Handlers) DecideApproval(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.approvals.decide") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	var req struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Decision != "approved" && req.Decision != "rejected" {
		writeError(w, http.StatusBadRequest, "decision must be 'approved' or 'rejected'", "BAD_REQUEST")
		return
	}

	if err := governance.DecideApproval(r.Context(), h.pool, user.UserID, user.OrgID, id, req.Decision, req.Reason); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to decide approval")
		writeError(w, http.StatusUnprocessableEntity, err.Error(), "UNPROCESSABLE")
		return
	}

	h.emitAuditEvent(r.Context(), "governance.approval.decided", "user", user.UserID, "approval", id, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "decision": req.Decision})
}

// ActivateEmergencyStop activates an emergency stop for the given scope.
func (h *Handlers) ActivateEmergencyStop(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.emergency_stop.activate") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var req struct {
		Scope   string `json:"scope"`
		ScopeID string `json:"scope_id"`
		Reason  string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Scope == "" || req.Reason == "" {
		writeError(w, http.StatusBadRequest, "scope and reason are required", "BAD_REQUEST")
		return
	}

	stop := &governance.EmergencyStop{
		Scope:   req.Scope,
		ScopeID: req.ScopeID,
		Reason:  req.Reason,
	}

	if err := governance.ActivateEmergencyStop(r.Context(), h.pool, user.UserID, user.OrgID, stop); err != nil {
		h.logger.Error().Err(err).Msg("failed to activate emergency stop")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	// Publish NATS event
	if h.js != nil {
		msg := map[string]string{
			"stop_id":      stop.ID,
			"scope":        stop.Scope,
			"scope_id":     stop.ScopeID,
			"activated_by": user.UserID,
			"activated_at": stop.ActivatedAt.Format(time.RFC3339),
		}
		msgData, _ := json.Marshal(msg)
		if _, err := h.js.Publish(r.Context(), "governance.estop.activated", msgData); err != nil {
			h.logger.Error().Err(err).Msg("failed to publish estop activation")
		}
	}

	h.emitAuditEvent(r.Context(), "governance.emergency_stop.activated", "user", user.UserID, "emergency_stop", stop.ID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, stop)
}

// LiftEmergencyStop deactivates an active emergency stop.
func (h *Handlers) LiftEmergencyStop(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.emergency_stop.lift") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var req struct {
		StopID string `json:"stop_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.StopID == "" {
		writeError(w, http.StatusBadRequest, "stop_id is required", "BAD_REQUEST")
		return
	}

	if err := governance.LiftEmergencyStop(r.Context(), h.pool, user.UserID, user.OrgID, req.StopID); err != nil {
		h.logger.Error().Err(err).Str("stop_id", req.StopID).Msg("failed to lift emergency stop")
		writeError(w, http.StatusUnprocessableEntity, err.Error(), "UNPROCESSABLE")
		return
	}

	// Publish NATS event
	if h.js != nil {
		msg := map[string]string{
			"stop_id":  req.StopID,
			"lifted_by": user.UserID,
		}
		msgData, _ := json.Marshal(msg)
		if _, err := h.js.Publish(r.Context(), "governance.estop.lifted", msgData); err != nil {
			h.logger.Error().Err(err).Msg("failed to publish estop lift")
		}
	}

	h.emitAuditEvent(r.Context(), "governance.emergency_stop.lifted", "user", user.UserID, "emergency_stop", req.StopID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, map[string]string{"stop_id": req.StopID, "status": "lifted"})
}

// ListActiveEmergencyStops returns all active emergency stops for the org.
func (h *Handlers) ListActiveEmergencyStops(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.emergency_stop.activate") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	stops, err := governance.ListActiveStops(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list active emergency stops")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if stops == nil {
		stops = []governance.EmergencyStop{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"stops": stops})
}

// AssignFinding assigns a finding to a user/team.
func (h *Handlers) AssignFinding(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "findings.triage") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	findingID := r.PathValue("id")

	var req struct {
		AssignedTo string     `json:"assigned_to"`
		TeamID     string     `json:"team_id"`
		DueAt      *time.Time `json:"due_at"`
		Note       string     `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.AssignedTo == "" {
		writeError(w, http.StatusBadRequest, "assigned_to is required", "BAD_REQUEST")
		return
	}

	assignment := &governance.FindingAssignment{
		FindingID:  findingID,
		AssignedTo: req.AssignedTo,
		TeamID:     req.TeamID,
		DueAt:      req.DueAt,
		Note:       req.Note,
	}

	if err := governance.AssignFinding(r.Context(), h.pool, user.UserID, user.OrgID, assignment); err != nil {
		h.logger.Error().Err(err).Str("finding_id", findingID).Msg("failed to assign finding")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "finding.assigned", "user", user.UserID, "finding", findingID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, assignment)
}

// SetLegalHold enables or disables legal hold on a finding.
func (h *Handlers) SetLegalHold(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "findings.legal_hold") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	findingID := r.PathValue("id")

	var req struct {
		Hold   bool   `json:"hold"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	if err := governance.SetLegalHold(r.Context(), h.pool, user.UserID, user.OrgID, "finding", findingID, req.Hold, req.Reason); err != nil {
		h.logger.Error().Err(err).Str("finding_id", findingID).Msg("failed to set legal hold")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "finding.legal_hold.set", "user", user.UserID, "finding", findingID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, map[string]any{"finding_id": findingID, "hold": req.Hold})
}
