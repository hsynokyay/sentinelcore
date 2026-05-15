package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

type surfaceEntryResponse struct {
	ID               string   `json:"id"`
	ProjectID        string   `json:"project_id"`
	SurfaceType      string   `json:"type"`
	URL              string   `json:"url"`
	Method           string   `json:"method"`
	Exposure         string   `json:"exposure"`
	Title            *string  `json:"title,omitempty"`
	FindingIDs       []string `json:"finding_ids"`
	ObservationCount int      `json:"observation_count"`
	FirstSeenAt      string   `json:"first_seen_at"`
	LastSeenAt       string   `json:"last_seen_at"`
	ScanCount        int      `json:"scan_count"`
}

// ListSurfaceEntries returns attack surface inventory with optional filters.
func (h *Handlers) ListSurfaceEntries(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "findings.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.URL.Query().Get("project_id")
	surfaceType := r.URL.Query().Get("type")
	exposure := r.URL.Query().Get("exposure")
	hasFindings := r.URL.Query().Get("has_findings")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 100
	offset := 0
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}
	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
			offset = v
		}
	}

	var entries []surfaceEntryResponse

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		query := `SELECT id, project_id, surface_type, url, method, exposure, title,
				         finding_ids, observation_count, first_seen_at, last_seen_at, scan_count
				  FROM scans.surface_entries WHERE 1=1`
		args := []any{}
		argIdx := 1

		if projectID != "" {
			query += fmt.Sprintf(" AND project_id = $%d", argIdx)
			args = append(args, projectID)
			argIdx++
		}
		if surfaceType != "" {
			query += fmt.Sprintf(" AND surface_type = $%d", argIdx)
			args = append(args, surfaceType)
			argIdx++
		}
		if exposure != "" {
			query += fmt.Sprintf(" AND exposure = $%d", argIdx)
			args = append(args, exposure)
			argIdx++
		}
		if hasFindings == "true" {
			query += " AND array_length(finding_ids, 1) > 0"
		}

		query += fmt.Sprintf(" ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, limit, offset)

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var e surfaceEntryResponse
			var title *string
			var findingIDs []string
			var firstSeen, lastSeen interface{}
			if err := rows.Scan(&e.ID, &e.ProjectID, &e.SurfaceType, &e.URL, &e.Method,
				&e.Exposure, &title, &findingIDs, &e.ObservationCount, &firstSeen, &lastSeen, &e.ScanCount); err != nil {
				return err
			}
			e.Title = title
			if findingIDs == nil {
				e.FindingIDs = []string{}
			} else {
				e.FindingIDs = findingIDs
			}
			e.FirstSeenAt = fmt.Sprintf("%v", firstSeen)
			e.LastSeenAt = fmt.Sprintf("%v", lastSeen)
			entries = append(entries, e)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list surface entries")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if entries == nil {
		entries = []surfaceEntryResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetSurfaceStats returns aggregate statistics for the surface inventory.
func (h *Handlers) GetSurfaceStats(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "findings.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.URL.Query().Get("project_id")

	type statRow struct {
		SurfaceType string `json:"type"`
		Exposure    string `json:"exposure"`
		Count       int    `json:"count"`
	}

	var stats []statRow

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		query := `SELECT surface_type, exposure, COUNT(*)::int
				  FROM scans.surface_entries WHERE 1=1`
		args := []any{}
		argIdx := 1

		if projectID != "" {
			query += fmt.Sprintf(" AND project_id = $%d", argIdx)
			args = append(args, projectID)
			argIdx++
		}

		query += " GROUP BY surface_type, exposure ORDER BY surface_type, exposure"

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var s statRow
			if err := rows.Scan(&s.SurfaceType, &s.Exposure, &s.Count); err != nil {
				return err
			}
			stats = append(stats, s)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get surface stats")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if stats == nil {
		stats = []statRow{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"stats": stats})
}
