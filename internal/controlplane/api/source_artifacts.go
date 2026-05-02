package api

// SAST source artifact intake handlers.
//
// Operators upload source bundles (ZIP archives) via multipart/form-data. The
// controlplane validates them safely (magic bytes, per-entry and total size
// limits, traversal + symlink rejection via pkg/archive) before committing
// them to storage. Only metadata ever crosses the API boundary — raw file
// contents are never returned. The scan worker resolves artifacts by ID
// against the shared /app/artifacts bind mount.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/archive"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

// ArtifactStorageRoot is where uploaded bundles live. The controlplane
// container mounts this as a bind volume; the path must also be accessible
// to the SAST worker (which shares the same volume in the compose stack).
var ArtifactStorageRoot = func() string {
	if v := os.Getenv("ARTIFACT_STORAGE_ROOT"); v != "" {
		return v
	}
	return "/app/artifacts"
}

// sourceArtifactResponse is the public shape returned by every artifact
// endpoint. It contains NO path references the caller could use to fetch the
// raw bytes, and NO field that could leak environment state.
type sourceArtifactResponse struct {
	ID               string `json:"id"`
	ProjectID        string `json:"project_id"`
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
	Format           string `json:"format"`
	SizeBytes        int64  `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	EntryCount       int    `json:"entry_count"`
	UncompressedSize int64  `json:"uncompressed_size"`
	UploadedBy       string `json:"uploaded_by"`
	CreatedAt        string `json:"created_at"`
}

// CreateSourceArtifact accepts a multipart upload and persists metadata.
// POST /api/v1/projects/{id}/artifacts (multipart/form-data)
//
// Form fields:
//   file        — required, the zip archive
//   name        — optional display name (defaults to filename)
//   description — optional free-text
func (h *Handlers) CreateSourceArtifact(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "artifacts.create") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.PathValue("id")

	// Cap the incoming body to the archive limits + slack for form fields.
	limits := archive.DefaultLimits()
	maxBody := limits.MaxCompressedBytes + 1<<20 // +1 MiB for form metadata
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	// 32 MiB in-memory form buffer; larger uploads spill to disk automatically.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse upload: "+err.Error(), "BAD_REQUEST")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing 'file' form field", "BAD_REQUEST")
		return
	}
	defer file.Close()

	if header.Size > limits.MaxCompressedBytes {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("file exceeds %d byte limit", limits.MaxCompressedBytes), "BAD_REQUEST")
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = sanitizeDisplayName(header.Filename)
	}
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required", "BAD_REQUEST")
		return
	}
	description := strings.TrimSpace(r.FormValue("description"))

	// Stage the upload to a temp file under the storage root so the final
	// rename is atomic on the same filesystem. This also lets us hash and
	// validate before committing the row.
	if err := os.MkdirAll(ArtifactStorageRoot(), 0o750); err != nil {
		h.logger.Error().Err(err).Msg("failed to ensure artifact storage root")
		writeError(w, http.StatusInternalServerError, "storage unavailable", "INTERNAL_ERROR")
		return
	}

	tmp, err := os.CreateTemp(ArtifactStorageRoot(), ".upload-*.zip")
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to create temp file")
		writeError(w, http.StatusInternalServerError, "storage unavailable", "INTERNAL_ERROR")
		return
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		tmp.Close()
		_ = os.Remove(tmpPath)
	}

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hasher), file)
	if err != nil {
		cleanup()
		writeError(w, http.StatusBadRequest, "upload failed: "+err.Error(), "BAD_REQUEST")
		return
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		writeError(w, http.StatusInternalServerError, "storage write failed", "INTERNAL_ERROR")
		return
	}
	if written <= 0 {
		cleanup()
		writeError(w, http.StatusBadRequest, "uploaded file is empty", "BAD_REQUEST")
		return
	}

	// Magic-byte check (defence in depth; ValidateZipFile would also catch it).
	{
		f, openErr := os.Open(tmpPath)
		if openErr != nil {
			cleanup()
			writeError(w, http.StatusInternalServerError, "storage read failed", "INTERNAL_ERROR")
			return
		}
		ok := archive.LooksLikeZip(f)
		f.Close()
		if !ok {
			cleanup()
			writeError(w, http.StatusBadRequest, "file is not a valid ZIP archive", "BAD_REQUEST")
			return
		}
	}

	summary, err := archive.ValidateZipFile(tmpPath, limits)
	if err != nil {
		cleanup()
		if errors.Is(err, archive.ErrUnsafeZip) {
			writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
			return
		}
		h.logger.Error().Err(err).Msg("zip validation failed")
		writeError(w, http.StatusInternalServerError, "zip validation failed", "INTERNAL_ERROR")
		return
	}

	// Commit: rename temp to final id.zip, insert row under RLS.
	id := uuid.New().String()
	finalPath := filepath.Join(ArtifactStorageRoot(), id+".zip")
	if err := os.Rename(tmpPath, finalPath); err != nil {
		cleanup()
		h.logger.Error().Err(err).Msg("failed to finalize artifact")
		writeError(w, http.StatusInternalServerError, "storage commit failed", "INTERNAL_ERROR")
		return
	}

	sha := hex.EncodeToString(hasher.Sum(nil))
	var created sourceArtifactResponse

	rlsErr := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		// Verify the project exists under RLS before inserting.
		var exists bool
		if qErr := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core.projects WHERE id = $1)`, projectID).Scan(&exists); qErr != nil {
			return qErr
		}
		if !exists {
			return errNotVisible
		}

		var createdAt time.Time
		if insErr := conn.QueryRow(ctx,
			`INSERT INTO scans.source_artifacts
			   (id, project_id, name, description, format, storage_path, size_bytes, sha256_hex, entry_count, uncompressed_size, uploaded_by, created_at)
			 VALUES ($1,$2,$3,$4,'zip',$5,$6,$7,$8,$9,$10,now())
			 RETURNING created_at`,
			id, projectID, name, nullIfEmpty(description), finalPath, written, sha, summary.EntryCount, summary.UncompressedSize, user.UserID,
		).Scan(&createdAt); insErr != nil {
			return insErr
		}

		created = sourceArtifactResponse{
			ID:               id,
			ProjectID:        projectID,
			Name:             name,
			Description:      description,
			Format:           "zip",
			SizeBytes:        written,
			SHA256:           sha,
			EntryCount:       summary.EntryCount,
			UncompressedSize: summary.UncompressedSize,
			UploadedBy:       user.UserID,
			CreatedAt:        createdAt.Format(time.RFC3339),
		}
		return nil
	})
	if rlsErr != nil {
		// On any DB failure, remove the committed file so we don't leak bytes.
		_ = os.Remove(finalPath)
		if rlsErr == errNotVisible {
			writeError(w, http.StatusNotFound, "project not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(rlsErr).Msg("failed to insert source artifact")
		writeError(w, http.StatusInternalServerError, "failed to store artifact metadata", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "artifact.create", "user", user.UserID, "source_artifact", id, r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, map[string]any{"source_artifact": created})
}

// ListSourceArtifacts returns metadata for all artifacts in a project.
// GET /api/v1/projects/{id}/artifacts
func (h *Handlers) ListSourceArtifacts(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "artifacts.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.PathValue("id")
	var artifacts []sourceArtifactResponse

	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		rows, qErr := conn.Query(ctx,
			`SELECT id, project_id, name, COALESCE(description,''), format,
			        size_bytes, sha256_hex, entry_count, uncompressed_size,
			        uploaded_by::text, created_at
			   FROM scans.source_artifacts
			  WHERE project_id = $1
			  ORDER BY created_at DESC`, projectID)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()
		for rows.Next() {
			var a sourceArtifactResponse
			var createdAt time.Time
			if sErr := rows.Scan(&a.ID, &a.ProjectID, &a.Name, &a.Description, &a.Format,
				&a.SizeBytes, &a.SHA256, &a.EntryCount, &a.UncompressedSize,
				&a.UploadedBy, &createdAt); sErr != nil {
				return sErr
			}
			a.CreatedAt = createdAt.Format(time.RFC3339)
			artifacts = append(artifacts, a)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list artifacts")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	if artifacts == nil {
		artifacts = []sourceArtifactResponse{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"source_artifacts": artifacts})
}

// GetSourceArtifact returns a single artifact's metadata.
// GET /api/v1/artifacts/{id}
func (h *Handlers) GetSourceArtifact(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "artifacts.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")
	var a sourceArtifactResponse
	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		var createdAt time.Time
		if qErr := conn.QueryRow(ctx,
			`SELECT id, project_id, name, COALESCE(description,''), format,
			        size_bytes, sha256_hex, entry_count, uncompressed_size,
			        uploaded_by::text, created_at
			   FROM scans.source_artifacts WHERE id = $1`, id,
		).Scan(&a.ID, &a.ProjectID, &a.Name, &a.Description, &a.Format,
			&a.SizeBytes, &a.SHA256, &a.EntryCount, &a.UncompressedSize,
			&a.UploadedBy, &createdAt); qErr != nil {
			return qErr
		}
		a.CreatedAt = createdAt.Format(time.RFC3339)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "source artifact not found", "NOT_FOUND")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"source_artifact": a})
}

// DeleteSourceArtifact removes an artifact row and its file.
// DELETE /api/v1/artifacts/{id}
func (h *Handlers) DeleteSourceArtifact(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "artifacts.delete") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	var storagePath string
	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		// DELETE ... RETURNING gives us the path under RLS in one round trip.
		qErr := conn.QueryRow(ctx,
			`DELETE FROM scans.source_artifacts WHERE id = $1 RETURNING storage_path`, id,
		).Scan(&storagePath)
		if qErr != nil {
			return errNotVisible
		}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "source artifact not found", "NOT_FOUND")
		return
	}

	// Defensive: only unlink paths inside the storage root.
	if storagePath != "" && strings.HasPrefix(filepath.Clean(storagePath), filepath.Clean(ArtifactStorageRoot())+string(os.PathSeparator)) {
		_ = os.Remove(storagePath)
	}

	h.emitAuditEvent(r.Context(), "artifact.delete", "user", user.UserID, "source_artifact", id, r.RemoteAddr, "success")
	w.WriteHeader(http.StatusNoContent)
}

// sanitizeDisplayName strips directory components and dangerous characters
// from a filename before using it as a display name. Returns "" for empty or
// fully-stripped input.
func sanitizeDisplayName(name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	base := filepath.Base(name)
	base = strings.TrimSpace(base)
	cleaned := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, base)
	if cleaned == "." || cleaned == ".." {
		return ""
	}
	return cleaned
}
