package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

type createScanTargetRequest struct {
	TargetType string `json:"target_type"`
	Identifier string `json:"identifier"`
	Label      string `json:"label"`
}

type scanTargetResponse struct {
	ID                 string  `json:"id"`
	ProjectID          string  `json:"project_id"`
	TargetType         string  `json:"target_type"`
	Identifier         string  `json:"identifier"`
	Label              string  `json:"label"`
	VerificationStatus string  `json:"verification_status"`
	CreatedAt          string  `json:"created_at"`
	VerifiedAt         *string `json:"verified_at,omitempty"`
}

// CreateScanTarget creates a scan target for a project.
func (h *Handlers) CreateScanTarget(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "targets.create") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.PathValue("id")

	var req createScanTargetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.TargetType == "" || req.Identifier == "" {
		writeError(w, http.StatusBadRequest, "target_type and identifier are required", "BAD_REQUEST")
		return
	}
	if req.Label == "" {
		req.Label = req.Identifier
	}

	id := uuid.New().String()
	now := time.Now().UTC()

	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO core.scan_targets (id, project_id, target_type, identifier, label, verification_status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $6)`,
		id, projectID, req.TargetType, req.Identifier, req.Label, now,
	)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to create scan target")
		writeError(w, http.StatusInternalServerError, "failed to create scan target", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "target.create", "user", user.UserID, "scan_target", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusCreated, scanTargetResponse{
		ID:                 id,
		ProjectID:          projectID,
		TargetType:         req.TargetType,
		Identifier:         req.Identifier,
		Label:              req.Label,
		VerificationStatus: "pending",
		CreatedAt:          now.Format(time.RFC3339),
	})
}

// ListScanTargets lists scan targets for a project.
func (h *Handlers) ListScanTargets(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "targets.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.PathValue("id")

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, project_id, target_type, identifier, label, verification_status, created_at, verified_at
		 FROM core.scan_targets WHERE project_id = $1 ORDER BY created_at DESC`, projectID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list scan targets")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	defer rows.Close()

	var targets []scanTargetResponse
	for rows.Next() {
		var t scanTargetResponse
		var createdAt time.Time
		var verifiedAt *time.Time
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.TargetType, &t.Identifier, &t.Label, &t.VerificationStatus, &createdAt, &verifiedAt); err != nil {
			h.logger.Error().Err(err).Msg("failed to scan target")
			writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
			return
		}
		t.CreatedAt = createdAt.Format(time.RFC3339)
		if verifiedAt != nil {
			v := verifiedAt.Format(time.RFC3339)
			t.VerifiedAt = &v
		}
		targets = append(targets, t)
	}

	if targets == nil {
		targets = []scanTargetResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"scan_targets": targets})
}
