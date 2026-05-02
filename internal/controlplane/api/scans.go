package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/governance"
	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

type createScanRequest struct {
	ScanType         string         `json:"scan_type"`
	TargetID         string         `json:"target_id,omitempty"`          // required for DAST, optional for SAST
	SourceArtifactID string         `json:"source_artifact_id,omitempty"` // required for SAST, optional for DAST
	ScanProfile      string         `json:"scan_profile,omitempty"`       // passive, standard, aggressive (default: standard)
	TriggerType      string         `json:"trigger_type,omitempty"`       // manual, scheduled, cicd, rescan, api (default: manual)
	ConfigOverride   map[string]any `json:"config_override,omitempty"`    // label, environment, etc. Max 4KB.
	Parameters       any            `json:"parameters,omitempty"`
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
	ID                 string  `json:"id"`
	ProjectID          string  `json:"project_id"`
	ProjectName        string  `json:"project_name,omitempty"`
	ScanType           string  `json:"scan_type"`
	ScanProfile        string  `json:"scan_profile,omitempty"`
	TriggerType        string  `json:"trigger_type,omitempty"`
	Status             string  `json:"status"`
	Progress           int     `json:"progress"`
	ProgressPhase      string  `json:"progress_phase,omitempty"`
	TargetID           string  `json:"target_id,omitempty"`
	TargetLabel        string  `json:"target_label,omitempty"`
	TargetBaseURL      string  `json:"target_base_url,omitempty"`
	SourceArtifactID   string  `json:"source_artifact_id,omitempty"`
	SourceArtifactName string  `json:"source_artifact_name,omitempty"`
	AuthProfileID      string  `json:"auth_profile_id,omitempty"`
	AuthProfileName    string  `json:"auth_profile_name,omitempty"`
	AuthProfileType    string  `json:"auth_profile_type,omitempty"`
	CreatedBy          string  `json:"created_by,omitempty"`
	CreatedAt          string  `json:"created_at"`
	StartedAt          *string `json:"started_at,omitempty"`
	FinishedAt         *string `json:"finished_at,omitempty"`
	ErrorMessage       string  `json:"error_message,omitempty"`
}

// scanSelectColumns is the shared SELECT for list/get so both endpoints return
// the same enriched shape. It left-joins projects, scan_targets, auth_configs,
// and source_artifacts so the UI never has to do N+1 lookups.
const scanSelectColumns = `
	sj.id, sj.project_id, COALESCE(p.display_name, p.name, '') AS project_name,
	sj.scan_type, sj.scan_profile, sj.trigger_type, sj.status,
	COALESCE((sj.progress->>'percent')::int, 0) AS progress_pct,
	COALESCE(sj.progress->>'phase', '') AS progress_phase,
	COALESCE(sj.scan_target_id::text, '') AS target_id,
	COALESCE(t.label, '') AS target_label,
	COALESCE(t.base_url, '') AS target_base_url,
	COALESCE(sj.source_ref->>'artifact_id', '') AS source_artifact_id,
	COALESCE(sa.name, '') AS source_artifact_name,
	COALESCE(t.auth_config_id::text, '') AS auth_profile_id,
	COALESCE(ac.name, '') AS auth_profile_name,
	COALESCE(ac.auth_type, '') AS auth_profile_type,
	sj.created_by::text, sj.created_at, sj.started_at, sj.completed_at,
	COALESCE(sj.error_message, '')`

const scanJoinClause = `
	FROM scans.scan_jobs sj
	LEFT JOIN core.projects p ON p.id = sj.project_id
	LEFT JOIN core.scan_targets t ON t.id = sj.scan_target_id
	LEFT JOIN auth.auth_configs ac ON ac.id = t.auth_config_id
	LEFT JOIN scans.source_artifacts sa ON sa.id::text = (sj.source_ref->>'artifact_id')`

// scanRowScan reads one row produced by scanSelectColumns into a scanResponse.
func scanRowScan(row pgx.Row, s *scanResponse) error {
	var createdAt time.Time
	var startedAt, finishedAt *time.Time
	if err := row.Scan(
		&s.ID, &s.ProjectID, &s.ProjectName,
		&s.ScanType, &s.ScanProfile, &s.TriggerType, &s.Status,
		&s.Progress, &s.ProgressPhase,
		&s.TargetID, &s.TargetLabel, &s.TargetBaseURL,
		&s.SourceArtifactID, &s.SourceArtifactName,
		&s.AuthProfileID, &s.AuthProfileName, &s.AuthProfileType,
		&s.CreatedBy, &createdAt, &startedAt, &finishedAt,
		&s.ErrorMessage,
	); err != nil {
		return err
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
	return nil
}

// validScanTypes mirrors the DB CHECK constraint on scans.scan_jobs.scan_type.
// "full" runs both SAST and DAST in one job.
var validScanTypes = map[string]bool{
	"sast": true,
	"dast": true,
	"full": true,
}

// validTriggerTypes mirrors the DB CHECK constraint on scan_jobs.trigger_type.
var validTriggerTypes = map[string]bool{
	"manual":    true,
	"scheduled": true,
	"cicd":      true,
	"rescan":    true,
	"api":       true,
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
		query := "SELECT " + scanSelectColumns + scanJoinClause + " WHERE 1=1"
		args := []any{}
		argIdx := 1

		if projectID != "" {
			query += fmt.Sprintf(" AND sj.project_id = $%d", argIdx)
			args = append(args, projectID)
			argIdx++
		}
		if status != "" {
			query += fmt.Sprintf(" AND sj.status = $%d", argIdx)
			args = append(args, status)
			argIdx++
		}
		if scanType != "" {
			query += fmt.Sprintf(" AND sj.scan_type = $%d", argIdx)
			args = append(args, scanType)
			argIdx++
		}

		query += fmt.Sprintf(" ORDER BY sj.created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, limit, offset)

		rows, err := conn.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var s scanResponse
			if err := scanRowScan(rows, &s); err != nil {
				return err
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
		writeError(w, http.StatusBadRequest, "invalid scan_type: must be sast, dast, or full", "BAD_REQUEST")
		return
	}
	triggerType := "manual"
	if req.TriggerType != "" {
		if !validTriggerTypes[req.TriggerType] {
			writeError(w, http.StatusBadRequest, "invalid trigger_type: must be manual, scheduled, cicd, rescan, or api", "BAD_REQUEST")
			return
		}
		triggerType = req.TriggerType
	}
	// Input selection: DAST/full need a target; SAST needs either a target
	// (for legacy git-based scans) or a source_artifact_id (new path).
	switch req.ScanType {
	case "dast":
		if req.TargetID == "" {
			writeError(w, http.StatusBadRequest, "target_id is required for dast scans", "BAD_REQUEST")
			return
		}
	case "sast":
		if req.TargetID == "" && req.SourceArtifactID == "" {
			writeError(w, http.StatusBadRequest, "sast scans require either target_id or source_artifact_id", "BAD_REQUEST")
			return
		}
	case "full":
		if req.TargetID == "" {
			writeError(w, http.StatusBadRequest, "target_id is required for full scans", "BAD_REQUEST")
			return
		}
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

	// Emergency-stop gate: block new scans if the org (or this specific
	// project) is currently under an active emergency stop.
	if stopped, stopErr := governance.IsEmergencyStopped(r.Context(), h.pool, user.OrgID, "project", projectID); stopErr != nil {
		h.logger.Error().Err(stopErr).Msg("failed to check emergency stop")
		writeError(w, http.StatusInternalServerError, "failed to validate scan", "INTERNAL_ERROR")
		return
	} else if stopped {
		writeError(w, http.StatusForbidden, "scans are blocked by an active emergency stop", "EMERGENCY_STOPPED")
		return
	}

	// All tenant-scoped lookups run under RLS so a caller can never probe
	// foreign resources by id. This also tightens the error surface — a
	// cross-org id now returns 404 instead of 400 (project-scope mismatch).
	id := uuid.New().String()
	now := time.Now().UTC()
	configJSON, _ := json.Marshal(req.ConfigOverride)

	var targetAuthConfigID *string
	var sourceRefJSON []byte
	if req.SourceArtifactID != "" {
		sourceRefJSON, _ = json.Marshal(map[string]string{"artifact_id": req.SourceArtifactID})
	}
	var scanTargetID any
	if req.TargetID != "" {
		scanTargetID = req.TargetID
	}

	rlsErr := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		// 1. Project must be visible under RLS.
		var projectVisible bool
		if qErr := conn.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM core.projects WHERE id = $1)`, projectID,
		).Scan(&projectVisible); qErr != nil {
			return qErr
		}
		if !projectVisible {
			return errNotVisible
		}

		// 2. Target (if supplied) must belong to the same project.
		if req.TargetID != "" {
			var targetProjectID string
			if qErr := conn.QueryRow(ctx,
				`SELECT project_id::text, auth_config_id::text FROM core.scan_targets WHERE id = $1`, req.TargetID,
			).Scan(&targetProjectID, &targetAuthConfigID); qErr != nil {
				if errors.Is(qErr, pgx.ErrNoRows) {
					return userError{code: http.StatusBadRequest, msg: "target not found"}
				}
				return qErr
			}
			if targetProjectID != projectID {
				return userError{code: http.StatusBadRequest, msg: "target does not belong to this project"}
			}
		}

		// 3. Source artifact (if supplied) must belong to the same project.
		if req.SourceArtifactID != "" {
			var artifactProjectID string
			if qErr := conn.QueryRow(ctx,
				`SELECT project_id::text FROM scans.source_artifacts WHERE id = $1`, req.SourceArtifactID,
			).Scan(&artifactProjectID); qErr != nil {
				if errors.Is(qErr, pgx.ErrNoRows) {
					return userError{code: http.StatusBadRequest, msg: "source_artifact not found"}
				}
				return qErr
			}
			if artifactProjectID != projectID {
				return userError{code: http.StatusBadRequest, msg: "source_artifact does not belong to this project"}
			}
		}

		// 4. Insert. scan_target_id is nullable (SAST artifact-only); trigger_type
		// is NOT NULL; progress is jsonb.
		_, iErr := conn.Exec(ctx,
			`INSERT INTO scans.scan_jobs (id, project_id, scan_type, scan_profile, status, trigger_type, progress, scan_target_id, source_ref, config_override, created_by, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, 'pending', $5, '{"phase":"pending","percent":0}'::jsonb, $6, $7, $8, $9, $10, $10)`,
			id, projectID, req.ScanType, scanProfile, triggerType, scanTargetID, sourceRefJSON, configJSON, user.UserID, now,
		)
		return iErr
	})
	if rlsErr != nil {
		if ue, ok := rlsErr.(userError); ok {
			writeError(w, ue.code, ue.msg, "BAD_REQUEST")
			return
		}
		if rlsErr == errNotVisible {
			writeError(w, http.StatusNotFound, "project not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(rlsErr).Msg("failed to create scan job")
		writeError(w, http.StatusInternalServerError, "failed to create scan", "INTERNAL_ERROR")
		return
	}

	// Dispatch scan via NATS. The envelope is intentionally thin — workers
	// resolve target/auth/scope from the database using scan_job_id rather
	// than carrying duplicated state on the wire (which goes stale fast).
	//
	// Both `scan_id` and `scan_job_id` are emitted for the same UUID so
	// SAST (reads scan_id) and DAST (reads scan_job_id) both work without a
	// coordinated rollout.
	subject := fmt.Sprintf("scan.%s.dispatch", req.ScanType)
	dispatchMsg := map[string]any{
		"scan_id":     id,
		"scan_job_id": id,
		"project_id":  projectID,
		"scan_type":   req.ScanType,
		"parameters":  req.Parameters,
	}
	if req.TargetID != "" {
		dispatchMsg["target_id"] = req.TargetID
	}
	if req.SourceArtifactID != "" {
		dispatchMsg["source_artifact_id"] = req.SourceArtifactID
		h.emitAuditEvent(r.Context(), "artifact.use", "user", user.UserID, "source_artifact", req.SourceArtifactID, r.RemoteAddr, "success")
	}
	if targetAuthConfigID != nil && *targetAuthConfigID != "" {
		dispatchMsg["auth_config_id"] = *targetAuthConfigID
		h.emitAuditEvent(r.Context(), "authprofile.use", "user", user.UserID, "auth_profile", *targetAuthConfigID, r.RemoteAddr, "success")
	}
	msgData, _ := json.Marshal(dispatchMsg)

	if h.js != nil {
		if _, err := h.js.Publish(r.Context(), subject, msgData); err != nil {
			h.logger.Error().Err(err).Str("subject", subject).Msg("failed to publish scan dispatch")
			// Don't fail the request — the scan is created, worker will pick it up on retry
		}
	}

	h.emitAuditEvent(r.Context(), "scan.create", "user", user.UserID, "scan", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusCreated, map[string]any{
		"scan": scanResponse{
			ID:               id,
			ProjectID:        projectID,
			ScanType:         req.ScanType,
			ScanProfile:      scanProfile,
			TriggerType:      triggerType,
			Status:           "queued",
			Progress:         0,
			ProgressPhase:    "pending",
			TargetID:         req.TargetID,
			SourceArtifactID: req.SourceArtifactID,
			CreatedBy:        user.UserID,
			CreatedAt:        now.Format(time.RFC3339),
		},
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
	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		row := conn.QueryRow(ctx, "SELECT "+scanSelectColumns+scanJoinClause+" WHERE sj.id = $1", id)
		return scanRowScan(row, &s)
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found", "NOT_FOUND")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"scan": s})
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
