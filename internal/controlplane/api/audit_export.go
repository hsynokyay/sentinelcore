package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/audit/export"
	"github.com/sentinelcore/sentinelcore/internal/audit/query"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// Sync-export hard cap. Larger exports need the async path (MinIO +
// job queue); that lands once MinIO is wired into prod compose.
const auditExportSyncCap = 10_000

// ListAuditExports handles GET /api/v1/audit/exports.
// Returns the caller's org export history (every request is logged
// whether inline-delivered or async).
func (h *Handlers) ListAuditExports(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	rows, err := h.pool.Query(r.Context(), `
		SELECT id::text, requested_by, requested_at, format,
		       status, progress_rows, COALESCE(total_rows, 0),
		       started_at, finished_at, delivered_inline,
		       COALESCE(object_key, ''), COALESCE(size_bytes, 0),
		       COALESCE(error_message, '')
		FROM audit.export_jobs
		WHERE org_id = $1
		ORDER BY requested_at DESC
		LIMIT 100
	`, p.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("list export jobs")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	defer rows.Close()

	type jobRow struct {
		ID              string     `json:"id"`
		RequestedBy     string     `json:"requested_by"`
		RequestedAt     time.Time  `json:"requested_at"`
		Format          string     `json:"format"`
		Status          string     `json:"status"`
		ProgressRows    int64      `json:"progress_rows"`
		TotalRows       int64      `json:"total_rows"`
		StartedAt       *time.Time `json:"started_at,omitempty"`
		FinishedAt      *time.Time `json:"finished_at,omitempty"`
		DeliveredInline bool       `json:"delivered_inline"`
		ObjectKey       string     `json:"object_key,omitempty"`
		SizeBytes       int64      `json:"size_bytes,omitempty"`
		ErrorMessage    string     `json:"error_message,omitempty"`
	}
	var out []jobRow
	for rows.Next() {
		var j jobRow
		var started, finished *time.Time
		if err := rows.Scan(&j.ID, &j.RequestedBy, &j.RequestedAt,
			&j.Format, &j.Status, &j.ProgressRows, &j.TotalRows,
			&started, &finished, &j.DeliveredInline,
			&j.ObjectKey, &j.SizeBytes, &j.ErrorMessage); err != nil {
			h.logger.Error().Err(err).Msg("scan export job")
			writeError(w, http.StatusInternalServerError, "scan", "INTERNAL")
			return
		}
		j.StartedAt = started
		j.FinishedAt = finished
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

// CreateAuditExport handles POST /api/v1/audit/exports. The response
// body IS the export artifact (CSV or NDJSON), streamed as rows are
// read. The job row in audit.export_jobs records the compliance
// metadata (who/what/when); a successful return marks the job 'succeeded'.
//
// Sync-only for now. When MinIO + GPG land in prod compose, the async
// branch (status=queued, returns 202 with job id) will live alongside
// this one behind an ?async=true query flag.
func (h *Handlers) CreateAuditExport(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}

	var req struct {
		Filters map[string]any `json:"filters"`
		Format  string         `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", "BAD_REQUEST")
		return
	}
	defer r.Body.Close()

	if req.Format != "csv" && req.Format != "ndjson" {
		writeError(w, http.StatusBadRequest, "format must be csv|ndjson", "BAD_REQUEST")
		return
	}

	f, err := filterFromMap(req.Filters)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}
	if err := f.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}

	// Insert the job row first so concurrent listers see it.
	jobID := uuid.New().String()
	filterJSON, _ := json.Marshal(req.Filters)
	if _, err := h.pool.Exec(r.Context(), `
		INSERT INTO audit.export_jobs (
		    id, org_id, requested_by, filters, format,
		    status, delivered_inline, started_at
		) VALUES ($1, $2, $3, $4, $5, 'running', true, now())
	`, jobID, p.OrgID, p.UserID, filterJSON, req.Format); err != nil {
		h.logger.Error().Err(err).Msg("audit export: job insert")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}

	// Emit the audit event BEFORE streaming so a client disconnect
	// mid-stream still leaves an audit trail of the attempt.
	if h.emitter != nil {
		_ = h.emitter.Emit(r.Context(), audit.AuditEvent{
			ActorType:    p.Kind,
			ActorID:      p.UserID,
			ActorIP:      clientIP(r),
			Action:       string(audit.AuditExportRequested),
			ResourceType: "audit_export",
			ResourceID:   jobID,
			OrgID:        p.OrgID,
			Result:       "success",
			Details: map[string]any{
				"format":  req.Format,
				"filters": req.Filters,
			},
		})
	}

	built := f.Build()
	where := built.Where
	args := append([]any{}, built.Args...)
	args = append(args, p.OrgID)
	orgPred := fmt.Sprintf("org_id = $%d", len(args))
	if where == "" {
		where = "WHERE " + orgPred
	} else {
		where += " AND " + orgPred
	}
	args = append(args, auditExportSyncCap+1) // +1 so we can detect truncation
	limitPos := len(args)

	sql := fmt.Sprintf(`
		SELECT %s
		FROM audit.audit_log
		%s
		ORDER BY timestamp DESC, id DESC
		LIMIT $%d
	`, export.ScanSelect, where, limitPos)

	rows, err := h.pool.Query(r.Context(), sql, args...)
	if err != nil {
		h.logger.Error().Err(err).Str("job", jobID).Msg("export query")
		_, _ = h.pool.Exec(r.Context(),
			`UPDATE audit.export_jobs SET status='failed', error_message=$2, finished_at=now() WHERE id=$1`,
			jobID, err.Error())
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	defer rows.Close()

	switch req.Format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="audit-%s.csv"`, jobID))
	case "ndjson":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="audit-%s.ndjson"`, jobID))
	}
	w.Header().Set("X-Export-Job-ID", jobID)

	var writer interface {
		WriteHeader() error
		Write(export.AuditRow) error
	}
	if req.Format == "csv" {
		writer = export.NewCSVWriter(w)
	} else {
		writer = export.NewNDJSONWriter(w)
	}
	if err := writer.WriteHeader(); err != nil {
		h.logger.Error().Err(err).Str("job", jobID).Msg("export header")
		return
	}

	var n int
	var truncated bool
	for rows.Next() {
		if n >= auditExportSyncCap {
			truncated = true
			break
		}
		var ar export.AuditRow
		if err := export.ScanRow(rows, &ar); err != nil {
			h.logger.Error().Err(err).Msg("export scan")
			break
		}
		if err := writer.Write(ar); err != nil {
			h.logger.Error().Err(err).Msg("export write")
			break
		}
		n++
	}

	errMsg := ""
	if truncated {
		errMsg = fmt.Sprintf("truncated at %d rows (sync cap); use async export for larger windows", auditExportSyncCap)
	}
	_, _ = h.pool.Exec(r.Context(), `
		UPDATE audit.export_jobs
		SET status='succeeded', progress_rows=$2, total_rows=$2,
		    finished_at=now(), error_message=NULLIF($3, '')
		WHERE id=$1
	`, jobID, n, errMsg)
}

// filterFromMap converts the POST body's filter object to a query.Filter.
// String fields + "actions" list + ISO8601 "from"/"to".
func filterFromMap(m map[string]any) (query.Filter, error) {
	var f query.Filter
	if s, ok := m["from"].(string); ok && s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return f, fmt.Errorf("filters.from: %w", err)
		}
		f.From = &t
	}
	if s, ok := m["to"].(string); ok && s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return f, fmt.Errorf("filters.to: %w", err)
		}
		f.To = &t
	}
	if raw, ok := m["actions"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok {
				f.Actions = append(f.Actions, s)
			}
		}
	}
	if s, ok := m["actor"].(string); ok {
		f.ActorID = s
	}
	if s, ok := m["resource_type"].(string); ok {
		f.ResourceType = s
	}
	if s, ok := m["resource_id"].(string); ok {
		f.ResourceID = s
	}
	if s, ok := m["result"].(string); ok {
		f.Result = s
	}
	return f, nil
}
