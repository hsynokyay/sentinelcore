package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type createScanRequest struct {
	ScanType   string `json:"scan_type"`
	TargetID   string `json:"target_id"`
	Parameters any    `json:"parameters,omitempty"`
}

type scanResponse struct {
	ID         string  `json:"id"`
	ProjectID  string  `json:"project_id"`
	ScanType   string  `json:"scan_type"`
	Status     string  `json:"status"`
	Progress   int     `json:"progress"`
	TargetID   string  `json:"target_id"`
	CreatedAt  string  `json:"created_at"`
	StartedAt  *string `json:"started_at,omitempty"`
	FinishedAt *string `json:"finished_at,omitempty"`
}

var validScanTypes = map[string]bool{
	"sast": true,
	"dast": true,
	"sca":  true,
}

// CreateScan creates a new scan job and dispatches it via NATS.
func (h *Handlers) CreateScan(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	projectID := r.PathValue("id")

	var req createScanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if !validScanTypes[req.ScanType] {
		writeError(w, http.StatusBadRequest, "invalid scan_type: must be sast, dast, or sca", "BAD_REQUEST")
		return
	}
	if req.TargetID == "" {
		writeError(w, http.StatusBadRequest, "target_id is required", "BAD_REQUEST")
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC()

	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO scans.scan_jobs (id, project_id, scan_type, status, progress, target_id, initiated_by, created_at, updated_at)
		 VALUES ($1, $2, $3, 'queued', 0, $4, $5, $6, $6)`,
		id, projectID, req.ScanType, req.TargetID, user.UserID, now,
	)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to create scan job")
		writeError(w, http.StatusInternalServerError, "failed to create scan", "INTERNAL_ERROR")
		return
	}

	// Dispatch scan via NATS
	subject := fmt.Sprintf("scan.%s.dispatch", req.ScanType)
	dispatchMsg := map[string]any{
		"scan_id":    id,
		"project_id": projectID,
		"target_id":  req.TargetID,
		"scan_type":  req.ScanType,
		"parameters": req.Parameters,
	}
	msgData, _ := json.Marshal(dispatchMsg)

	if h.js != nil {
		if _, err := h.js.Publish(r.Context(), subject, msgData); err != nil {
			h.logger.Error().Err(err).Str("subject", subject).Msg("failed to publish scan dispatch")
			// Don't fail the request — the scan is created, worker will pick it up on retry
		}
	}

	h.emitAuditEvent(r.Context(), "scan.create", "user", user.UserID, "scan", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusCreated, scanResponse{
		ID:        id,
		ProjectID: projectID,
		ScanType:  req.ScanType,
		Status:    "queued",
		Progress:  0,
		TargetID:  req.TargetID,
		CreatedAt: now.Format(time.RFC3339),
	})
}

// GetScan gets a scan's status and progress.
func (h *Handlers) GetScan(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	id := r.PathValue("id")

	var s scanResponse
	var createdAt time.Time
	var startedAt, finishedAt *time.Time
	err := h.pool.QueryRow(r.Context(),
		`SELECT id, project_id, scan_type, status, progress, target_id, created_at, started_at, finished_at
		 FROM scans.scan_jobs WHERE id = $1`, id,
	).Scan(&s.ID, &s.ProjectID, &s.ScanType, &s.Status, &s.Progress, &s.TargetID, &createdAt, &startedAt, &finishedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found", "NOT_FOUND")
		return
	}
	s.CreatedAt = createdAt.Format(time.RFC3339)
	if startedAt != nil {
		v := startedAt.Format(time.RFC3339)
		s.StartedAt = &v
	}
	if finishedAt != nil {
		v := finishedAt.Format(time.RFC3339)
		s.FinishedAt = &v
	}

	writeJSON(w, http.StatusOK, s)
}

// CancelScan cancels a running or queued scan.
func (h *Handlers) CancelScan(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	id := r.PathValue("id")

	tag, err := h.pool.Exec(r.Context(),
		`UPDATE scans.scan_jobs SET status = 'cancelled', updated_at = now()
		 WHERE id = $1 AND status IN ('queued', 'running')`, id)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to cancel scan")
		writeError(w, http.StatusInternalServerError, "failed to cancel scan", "INTERNAL_ERROR")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusBadRequest, "scan cannot be cancelled (not queued or running)", "BAD_REQUEST")
		return
	}

	h.emitAuditEvent(r.Context(), "scan.cancel", "user", user.UserID, "scan", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}
