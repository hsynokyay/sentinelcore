package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/governance"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

// CreateApprovalRequestHandler exposes governance.CreateApprovalRequest over
// REST. POST /api/v1/governance/approvals
//
// Body:
//
//	{
//	  "request_type":      "risk_closure",
//	  "resource_type":     "finding",
//	  "resource_id":       "<uuid>",
//	  "reason":            "string",
//	  "required_approvals": 2,
//	  "target_transition": "resolved",
//	  "project_id":        "<uuid>"     // optional
//	  "team_id":           "<uuid>"     // optional
//	}
func (h *Handlers) CreateApprovalRequestHandler(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	// Creating an approval request is a triage-adjacent action. We require
	// the same permission as initiating triage so that read-only roles cannot
	// open closure requests.
	if !policy.Evaluate(user.Role, "findings.triage") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var body struct {
		RequestType       string  `json:"request_type"`
		ResourceType      string  `json:"resource_type"`
		ResourceID        string  `json:"resource_id"`
		Reason            string  `json:"reason"`
		RequiredApprovals int     `json:"required_approvals"`
		TargetTransition  string  `json:"target_transition"`
		ProjectID         *string `json:"project_id,omitempty"`
		TeamID            *string `json:"team_id,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if body.RequestType == "" || body.ResourceType == "" || body.ResourceID == "" {
		writeError(w, http.StatusBadRequest, "request_type, resource_type, resource_id are required", "BAD_REQUEST")
		return
	}
	if body.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required", "BAD_REQUEST")
		return
	}

	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	requesterID, err := uuid.Parse(user.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id on session", "BAD_REQUEST")
		return
	}
	resourceID, err := uuid.Parse(body.ResourceID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "resource_id must be a uuid", "BAD_REQUEST")
		return
	}

	in := governance.CreateApprovalReq{
		OrgID:             orgID,
		RequestedBy:       requesterID,
		RequestType:       body.RequestType,
		ResourceType:      body.ResourceType,
		ResourceID:        resourceID,
		Reason:            body.Reason,
		RequiredApprovals: body.RequiredApprovals,
		TargetTransition:  body.TargetTransition,
	}
	if body.ProjectID != nil && *body.ProjectID != "" {
		pid, perr := uuid.Parse(*body.ProjectID)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "project_id must be a uuid", "BAD_REQUEST")
			return
		}
		in.ProjectID = &pid
	}
	if body.TeamID != nil && *body.TeamID != "" {
		tid, terr := uuid.Parse(*body.TeamID)
		if terr != nil {
			writeError(w, http.StatusBadRequest, "team_id must be a uuid", "BAD_REQUEST")
			return
		}
		in.TeamID = &tid
	}

	out, err := governance.CreateApprovalRequest(r.Context(), h.pool, in)
	if err != nil {
		h.logger.Error().Err(err).Msg("create approval request")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "governance.approval.created", "user", user.UserID, "approval", out.ID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, out)
}

// SubmitApprovalDecision exposes governance.DecideApproval over REST.
// POST /api/v1/governance/approvals/{id}/decisions
//
// Body: { "decision": "approve" | "reject", "reason": "string" }
//
// Maps governance errors to status codes:
//   - ErrSelfApprovalForbidden → 403
//   - ErrDuplicateDecision     → 409
//   - ErrAlreadyDecided        → 409
//   - ErrExpired               → 410
//   - ErrApprovalNotFound      → 404
//
// On the second-approver flip to status='approved', this handler invokes
// governance.ExecuteApprovedTransition synchronously so the gated finding
// transition fires within the same request.
func (h *Handlers) SubmitApprovalDecision(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.approvals.decide") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required", "BAD_REQUEST")
		return
	}

	var body struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if body.Decision != "approve" && body.Decision != "reject" {
		writeError(w, http.StatusBadRequest, "decision must be 'approve' or 'reject'", "BAD_REQUEST")
		return
	}
	if body.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required", "REASON_REQUIRED")
		return
	}

	userID, err := uuid.Parse(user.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id on session", "BAD_REQUEST")
		return
	}

	updated, err := governance.DecideApproval(r.Context(), h.pool, id, userID, body.Decision, body.Reason)
	switch {
	case errors.Is(err, governance.ErrSelfApprovalForbidden):
		writeError(w, http.StatusForbidden, err.Error(), "SELF_APPROVAL_FORBIDDEN")
		return
	case errors.Is(err, governance.ErrDuplicateDecision):
		writeError(w, http.StatusConflict, err.Error(), "DUPLICATE_DECISION")
		return
	case errors.Is(err, governance.ErrAlreadyDecided):
		writeError(w, http.StatusConflict, err.Error(), "ALREADY_DECIDED")
		return
	case errors.Is(err, governance.ErrExpired):
		writeError(w, http.StatusGone, err.Error(), "EXPIRED")
		return
	case errors.Is(err, governance.ErrApprovalNotFound):
		writeError(w, http.StatusNotFound, err.Error(), "NOT_FOUND")
		return
	case err != nil:
		h.logger.Error().Err(err).Str("id", id).Msg("decide approval")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	auditAction := "governance.approval.approved"
	if body.Decision == "reject" {
		auditAction = "governance.approval.rejected"
	}
	h.emitAuditEvent(r.Context(), auditAction, "user", user.UserID, "approval", id, r.RemoteAddr, "success")

	// If this decision flipped the row to 'approved', execute the gated
	// transition synchronously. Failure here surfaces a 502 because the
	// decision succeeded but the downstream side-effect did not.
	if updated.Status == "approved" {
		if err := governance.ExecuteApprovedTransition(r.Context(), h.pool, id); err != nil {
			h.logger.Error().Err(err).Str("id", id).Msg("execute approved transition")
			writeError(w, http.StatusBadGateway, "approval recorded but transition failed: "+err.Error(), "TRANSITION_FAILED")
			return
		}
		updated.Status = "executed"
		h.emitAuditEvent(r.Context(), "governance.approval.executed", "user", user.UserID, "approval", id, r.RemoteAddr, "success")
	}

	writeJSON(w, http.StatusOK, updated)
}
