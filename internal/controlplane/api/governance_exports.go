// governance_exports.go — REST API for evidence pack export jobs.
//
// Routes:
//
//	POST  /api/v1/governance/exports             — request a new export
//	GET   /api/v1/governance/exports             — list org export jobs
//	GET   /api/v1/governance/exports/{id}        — fetch a single job
//	GET   /api/v1/governance/exports/{id}/download — download artefact
//
// The actual pack composition runs asynchronously in cmd/export-worker; the
// handlers here drive the queued -> running -> completed state machine
// from the request side.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/internal/export/evidence"
	"github.com/sentinelcore/sentinelcore/internal/governance/exportworker"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

// ExportJob is the wire representation of governance.export_jobs.
type ExportJob struct {
	ID           string         `json:"id"`
	OrgID        string         `json:"org_id"`
	RequestedBy  string         `json:"requested_by"`
	Kind         string         `json:"kind"`
	Scope        map[string]any `json:"scope"`
	Format       string         `json:"format"`
	Status       string         `json:"status"`
	ArtifactRef  string         `json:"artifact_ref,omitempty"`
	ArtifactHash string         `json:"artifact_hash,omitempty"`
	ArtifactSize int64          `json:"artifact_size,omitempty"`
	Error        string         `json:"error,omitempty"`
	StartedAt    *time.Time     `json:"started_at,omitempty"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	ExpiresAt    time.Time      `json:"expires_at"`
	CreatedAt    time.Time      `json:"created_at"`
}

// CreateExport handles POST /api/v1/governance/exports.
//
// Body:
//
//	{
//	  "kind":   "risk_evidence_pack" | "project_evidence_pack" | "custom",
//	  "scope":  { "risk_ids": [...], "project_id": "...", ... },
//	  "format": "zip_json" | "json"
//	}
//
// Returns 202 with the created job row.
func (h *Handlers) CreateExport(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.exports.write") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var body struct {
		Kind   string          `json:"kind"`
		Scope  json.RawMessage `json:"scope"`
		Format string          `json:"format"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if !validKind(body.Kind) {
		writeError(w, http.StatusBadRequest,
			"kind must be one of risk_evidence_pack, project_evidence_pack, custom",
			"BAD_REQUEST")
		return
	}
	if !validFormat(body.Format) {
		writeError(w, http.StatusBadRequest,
			"format must be one of zip_json, json",
			"BAD_REQUEST")
		return
	}
	if len(body.Scope) == 0 {
		body.Scope = []byte("{}")
	}
	// Round-trip the scope through the evidence.Scope type so we reject
	// payloads that we won't be able to deserialize in the worker.
	var sanityScope evidence.Scope
	if err := json.Unmarshal(body.Scope, &sanityScope); err != nil {
		writeError(w, http.StatusBadRequest, "scope is not a valid object", "BAD_REQUEST")
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

	if h.pool == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable", "DB_UNAVAILABLE")
		return
	}

	jobID, _, err := exportworker.EnqueueExport(r.Context(), h.pool, orgID, requesterID, body.Kind, body.Scope, body.Format)
	if err != nil {
		h.logger.Error().Err(err).Msg("enqueue export")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "governance.export.requested", "user", user.UserID, "export_job", jobID.String(), r.RemoteAddr, "success")

	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":     jobID.String(),
		"status": "queued",
		"kind":   body.Kind,
		"format": body.Format,
	})
}

// ListExports handles GET /api/v1/governance/exports.
func (h *Handlers) ListExports(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.exports.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if h.pool == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable", "DB_UNAVAILABLE")
		return
	}

	rows, err := h.pool.Query(r.Context(), `
		SELECT id, org_id, requested_by, kind, scope, format, status,
		       COALESCE(artifact_ref, ''), COALESCE(artifact_hash, ''), COALESCE(artifact_size, 0),
		       COALESCE(error, ''), started_at, completed_at, expires_at, created_at
		  FROM governance.export_jobs
		 WHERE org_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`, orgID, limit)
	if err != nil {
		h.logger.Error().Err(err).Msg("list exports")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	defer rows.Close()

	out := make([]ExportJob, 0)
	for rows.Next() {
		j, scanErr := scanExportJob(rows)
		if scanErr != nil {
			h.logger.Error().Err(scanErr).Msg("scan export job")
			writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
			return
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, map[string]any{"exports": out, "limit": limit})
}

// GetExport handles GET /api/v1/governance/exports/{id}.
func (h *Handlers) GetExport(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.exports.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a uuid", "BAD_REQUEST")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	if h.pool == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable", "DB_UNAVAILABLE")
		return
	}
	row := h.pool.QueryRow(r.Context(), `
		SELECT id, org_id, requested_by, kind, scope, format, status,
		       COALESCE(artifact_ref, ''), COALESCE(artifact_hash, ''), COALESCE(artifact_size, 0),
		       COALESCE(error, ''), started_at, completed_at, expires_at, created_at
		  FROM governance.export_jobs
		 WHERE id = $1 AND org_id = $2`, id, orgID)
	j, err := scanExportJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "export not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("get export")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, j)
}

// DownloadExport handles GET /api/v1/governance/exports/{id}/download.
//
// In the docker-compose deployment we serve the artefact bytes directly
// rather than redirecting to a presigned URL — the blob is on the local
// filesystem under exportworker's BlobClient. h.exportBlob is wired in
// server.go; tests that exercise download paths set it to a fake.
func (h *Handlers) DownloadExport(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "governance.exports.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a uuid", "BAD_REQUEST")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}

	if h.pool == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable", "DB_UNAVAILABLE")
		return
	}
	if h.exportBlob == nil {
		writeError(w, http.StatusServiceUnavailable, "blob store not configured", "BLOB_UNAVAILABLE")
		return
	}

	row := h.pool.QueryRow(r.Context(), `
		SELECT id, org_id, requested_by, kind, scope, format, status,
		       COALESCE(artifact_ref, ''), COALESCE(artifact_hash, ''), COALESCE(artifact_size, 0),
		       COALESCE(error, ''), started_at, completed_at, expires_at, created_at
		  FROM governance.export_jobs
		 WHERE id = $1 AND org_id = $2`, id, orgID)
	j, err := scanExportJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "export not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("get export for download")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	if j.Status != "completed" {
		writeError(w, http.StatusConflict, "export is not yet completed", "NOT_READY")
		return
	}
	if !j.ExpiresAt.After(time.Now()) {
		writeError(w, http.StatusGone, "export artifact has expired", "EXPIRED")
		return
	}
	if j.ArtifactRef == "" {
		writeError(w, http.StatusInternalServerError, "missing artifact ref", "INTERNAL_ERROR")
		return
	}

	rc, err := h.exportBlob.Get(j.ArtifactRef)
	if err != nil {
		if errors.Is(err, evidence.ErrBlobNotFound) {
			writeError(w, http.StatusNotFound, "artifact not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("blob get")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="evidence-pack-%s.zip"`, id))
	if j.ArtifactSize > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(j.ArtifactSize, 10))
	}
	if _, err := io.Copy(w, rc); err != nil {
		h.logger.Error().Err(err).Str("id", idStr).Msg("stream artifact")
		return
	}

	h.emitAuditEvent(r.Context(), "governance.export.downloaded", "user", user.UserID, "export_job", idStr, r.RemoteAddr, "success")
}

// scanExportJob abstracts row scanning for both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanExportJob(r rowScanner) (ExportJob, error) {
	var (
		j         ExportJob
		scopeRaw  []byte
		startedAt *time.Time
		completed *time.Time
	)
	err := r.Scan(
		&j.ID, &j.OrgID, &j.RequestedBy,
		&j.Kind, &scopeRaw, &j.Format, &j.Status,
		&j.ArtifactRef, &j.ArtifactHash, &j.ArtifactSize,
		&j.Error,
		&startedAt, &completed,
		&j.ExpiresAt, &j.CreatedAt,
	)
	if err != nil {
		return ExportJob{}, err
	}
	j.StartedAt = startedAt
	j.CompletedAt = completed
	if len(scopeRaw) > 0 {
		_ = json.Unmarshal(scopeRaw, &j.Scope)
	}
	if j.Scope == nil {
		j.Scope = map[string]any{}
	}
	return j, nil
}

func validKind(k string) bool {
	switch k {
	case "risk_evidence_pack", "project_evidence_pack", "custom":
		return true
	}
	return false
}

func validFormat(f string) bool {
	switch f {
	case "zip_json", "json":
		return true
	}
	return false
}
