package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

type createScanRequest struct {
	ScanType       string         `json:"scan_type"`
	TargetID       string         `json:"target_id"`
	ScanProfile    string         `json:"scan_profile,omitempty"`    // passive, standard, aggressive (default: standard)
	ConfigOverride map[string]any `json:"config_override,omitempty"` // label, environment, etc. Max 4KB.
	Parameters     any            `json:"parameters,omitempty"`
}

var validScanProfiles = map[string]bool{
	"passive":    true,
	"standard":   true,
	"aggressive": true,
}

// configOverrideAllowedKeys limits what can be stored in config_override.
var configOverrideAllowedKeys = map[string]bool{
	"label":       true,
	"environment": true,
	"notes":       true,
}

const maxConfigOverrideSize = 4096 // 4KB

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

// ListScans returns paginated scan jobs with optional filters.
func (h *Handlers) ListScans(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "scans.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.URL.Query().Get("project_id")
	status := r.URL.Query().Get("status")
	scanType := r.URL.Query().Get("scan_type")
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

	var scans []scanResponse

	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		query := `SELECT id, project_id, scan_type, status, COALESCE(progress, 0), COALESCE(target_id::text, ''), created_at, started_at, finished_at
				  FROM scans.scan_jobs WHERE 1=1`
		args := []any{}
		argIdx := 1

		if projectID != "" {
			query += fmt.Sprintf(" AND project_id = $%d", argIdx)
			args = append(args, projectID)
			argIdx++
		}
		if status != "" {
			query += fmt.Sprintf(" AND status = $%d", argIdx)
			args = append(args, status)
			argIdx++
		}
		if scanType != "" {
			query += fmt.Sprintf(" AND scan_type = $%d", argIdx)
			args = append(args, scanType)
			argIdx++
		}

		query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, limit, offset)

		rows, err := conn.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var s scanResponse
			var createdAt time.Time
			var startedAt, finishedAt *time.Time
			if err := rows.Scan(&s.ID, &s.ProjectID, &s.ScanType, &s.Status, &s.Progress, &s.TargetID, &createdAt, &startedAt, &finishedAt); err != nil {
				return err
			}
			s.CreatedAt = createdAt.Format(time.RFC3339)
			if startedAt != nil {
				t := startedAt.Format(time.RFC3339)
				s.StartedAt = &t
			}
			if finishedAt != nil {
				t := finishedAt.Format(time.RFC3339)
				s.FinishedAt = &t
			}
			scans = append(scans, s)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list scans")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if scans == nil {
		scans = []scanResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"scans":  scans,
		"limit":  limit,
		"offset": offset,
	})
}

// CreateScan creates a new scan job and dispatches it via NATS.
func (h *Handlers) CreateScan(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "scans.create") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
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

	// Validate scan_profile.
	scanProfile := "standard"
	if req.ScanProfile != "" {
		if !validScanProfiles[req.ScanProfile] {
			writeError(w, http.StatusBadRequest, "invalid scan_profile: must be passive, standard, or aggressive", "BAD_REQUEST")
			return
		}
		scanProfile = req.ScanProfile
	}

	// Validate config_override: size limit + allowed keys.
	if req.ConfigOverride != nil {
		overrideJSON, _ := json.Marshal(req.ConfigOverride)
		if len(overrideJSON) > maxConfigOverrideSize {
			writeError(w, http.StatusBadRequest, "config_override exceeds 4KB limit", "BAD_REQUEST")
			return
		}
		for key := range req.ConfigOverride {
			if !configOverrideAllowedKeys[key] {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("config_override key %q not allowed; allowed keys: label, environment, notes", key), "BAD_REQUEST")
				return
			}
		}
	}

	// Validate target belongs to this project.
	var targetProjectID string
	err := h.pool.QueryRow(r.Context(),
		`SELECT project_id FROM core.scan_targets WHERE id = $1`, req.TargetID,
	).Scan(&targetProjectID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "target not found", "BAD_REQUEST")
		return
	}
	if targetProjectID != projectID {
		writeError(w, http.StatusBadRequest, "target does not belong to this project", "BAD_REQUEST")
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC()
	configJSON, _ := json.Marshal(req.ConfigOverride)

	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO scans.scan_jobs (id, project_id, scan_type, scan_profile, status, progress, scan_target_id, config_override, created_by, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'pending', 0, $5, $6, $7, $8, $8)`,
		id, projectID, req.ScanType, scanProfile, req.TargetID, configJSON, user.UserID, now,
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
	if !policy.Evaluate(user.Role, "scans.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
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
	if !policy.Evaluate(user.Role, "scans.cancel") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
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
