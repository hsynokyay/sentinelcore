package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/db"
)

type findingResponse struct {
	ID          string `json:"id"`
	ProjectID   string `json:"project_id"`
	ScanID      string `json:"scan_id"`
	FindingType string `json:"finding_type"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Title       string `json:"title"`
	Description string `json:"description"`
	FilePath    string `json:"file_path,omitempty"`
	LineNumber  *int   `json:"line_number,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type updateFindingStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// ListFindings queries findings with filters, paginated and RLS-enforced.
func (h *Handlers) ListFindings(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	// Parse query params
	projectID := r.URL.Query().Get("project_id")
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	findingType := r.URL.Query().Get("finding_type")
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

	var findings []findingResponse

	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		query := `SELECT id, project_id, scan_id, finding_type, severity, status, title, COALESCE(description, ''), COALESCE(file_path, ''), line_number, created_at
				  FROM findings.findings WHERE 1=1`
		args := []any{}
		argIdx := 1

		if projectID != "" {
			query += fmt.Sprintf(" AND project_id = $%d", argIdx)
			args = append(args, projectID)
			argIdx++
		}
		if severity != "" {
			query += fmt.Sprintf(" AND severity = $%d", argIdx)
			args = append(args, severity)
			argIdx++
		}
		if status != "" {
			query += fmt.Sprintf(" AND status = $%d", argIdx)
			args = append(args, status)
			argIdx++
		}
		if findingType != "" {
			query += fmt.Sprintf(" AND finding_type = $%d", argIdx)
			args = append(args, findingType)
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
			var f findingResponse
			var createdAt time.Time
			var lineNumber *int
			if err := rows.Scan(&f.ID, &f.ProjectID, &f.ScanID, &f.FindingType, &f.Severity, &f.Status, &f.Title, &f.Description, &f.FilePath, &lineNumber, &createdAt); err != nil {
				return err
			}
			f.CreatedAt = createdAt.Format(time.RFC3339)
			f.LineNumber = lineNumber
			findings = append(findings, f)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list findings")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if findings == nil {
		findings = []findingResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"findings": findings,
		"limit":    limit,
		"offset":   offset,
	})
}

// UpdateFindingStatus updates a finding's status and records a state transition.
func (h *Handlers) UpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	id := r.PathValue("id")

	var req updateFindingStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Status == "" {
		writeError(w, http.StatusBadRequest, "status is required", "BAD_REQUEST")
		return
	}

	// Get current status
	var oldStatus string
	err := h.pool.QueryRow(r.Context(),
		`SELECT status FROM findings.findings WHERE id = $1`, id,
	).Scan(&oldStatus)
	if err != nil {
		writeError(w, http.StatusNotFound, "finding not found", "NOT_FOUND")
		return
	}

	// Update status
	_, err = h.pool.Exec(r.Context(),
		`UPDATE findings.findings SET status = $1, updated_at = now() WHERE id = $2`,
		req.Status, id)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to update finding status")
		writeError(w, http.StatusInternalServerError, "failed to update finding", "INTERNAL_ERROR")
		return
	}

	// Insert state transition record
	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO findings.finding_state_transitions (id, finding_id, from_status, to_status, changed_by, reason, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now())`,
		uuid.New().String(), id, oldStatus, req.Status, user.UserID, req.Reason)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to insert state transition")
		// Non-fatal: status update already succeeded
	}

	h.emitAuditEvent(r.Context(), "finding.status_update", "user", user.UserID, "finding", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusOK, map[string]string{
		"id":          id,
		"old_status":  oldStatus,
		"new_status":  req.Status,
	})
}
