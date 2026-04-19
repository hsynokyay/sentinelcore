package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

// validTargetTypes mirrors the CHECK constraint on core.scan_targets.target_type.
var validTargetTypes = map[string]bool{
	"web_app": true,
	"api":     true,
	"graphql": true,
}

const (
	defaultMaxRPS = 10
	maxRPSCeiling = 500
)

var defaultAllowedPorts = []int32{80, 443}

type scanTargetRequest struct {
	TargetType     string   `json:"target_type"`
	BaseURL        string   `json:"base_url"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	AllowedPaths   []string `json:"allowed_paths,omitempty"`
	ExcludedPaths  []string `json:"excluded_paths,omitempty"`
	AllowedPorts   []int32  `json:"allowed_ports,omitempty"`
	MaxRPS         *int     `json:"max_rps,omitempty"`
	Label          string   `json:"label,omitempty"`
	Environment    string   `json:"environment,omitempty"`
	Notes          string   `json:"notes,omitempty"`
	AuthConfigID   string   `json:"auth_config_id,omitempty"` // optional reference to auth.auth_configs
}

type scanTargetResponse struct {
	ID                 string   `json:"id"`
	ProjectID          string   `json:"project_id"`
	TargetType         string   `json:"target_type"`
	BaseURL            string   `json:"base_url"`
	AllowedDomains     []string `json:"allowed_domains"`
	AllowedPaths       []string `json:"allowed_paths,omitempty"`
	ExcludedPaths      []string `json:"excluded_paths,omitempty"`
	AllowedPorts       []int32  `json:"allowed_ports"`
	MaxRPS             int      `json:"max_rps"`
	Label              string   `json:"label,omitempty"`
	Environment        string   `json:"environment,omitempty"`
	Notes              string   `json:"notes,omitempty"`
	AuthConfigID       string   `json:"auth_config_id,omitempty"`
	VerificationStatus string   `json:"verification_status"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
	VerifiedAt         *string  `json:"verified_at,omitempty"`
}

// validateTargetRequest applies shared validation for create and update paths.
// The caller is responsible for ensuring required fields are populated before
// calling this function.
func validateTargetRequest(req *scanTargetRequest) (normalized scanTargetRequest, errMsg string) {
	if !validTargetTypes[req.TargetType] {
		return *req, "target_type must be one of: web_app, api, graphql"
	}
	parsed, err := url.Parse(strings.TrimSpace(req.BaseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return *req, "base_url must be an absolute URL including scheme and host"
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return *req, "base_url scheme must be http or https"
	}

	out := *req
	out.BaseURL = parsed.String()

	// Default allowed_domains to the base_url host if none supplied. We require
	// at least one domain at the DB level (NOT NULL), so the caller can omit
	// this field and get sensible scope.
	if len(out.AllowedDomains) == 0 {
		out.AllowedDomains = []string{parsed.Hostname()}
	}
	for i, d := range out.AllowedDomains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			return *req, "allowed_domains entries cannot be empty"
		}
		out.AllowedDomains[i] = d
	}

	if len(out.AllowedPorts) == 0 {
		out.AllowedPorts = defaultAllowedPorts
	} else {
		for _, p := range out.AllowedPorts {
			if p < 1 || p > 65535 {
				return *req, "allowed_ports entries must be between 1 and 65535"
			}
		}
	}

	if out.MaxRPS == nil {
		rps := defaultMaxRPS
		out.MaxRPS = &rps
	} else if *out.MaxRPS <= 0 || *out.MaxRPS > maxRPSCeiling {
		return *req, fmt.Sprintf("max_rps must be between 1 and %d", maxRPSCeiling)
	}

	if out.Label == "" {
		out.Label = parsed.Host
	}
	return out, ""
}

// scanRowInto scans a pgx.Row into a scanTargetResponse.
func scanRowInto(row pgx.Row, t *scanTargetResponse) error {
	var createdAt, updatedAt time.Time
	var verifiedAt *time.Time
	var label, environment, notes, authConfigID *string
	var allowedPaths, excludedPaths []string
	var allowedPortsInt32 []int32
	err := row.Scan(
		&t.ID, &t.ProjectID, &t.TargetType, &t.BaseURL,
		&t.AllowedDomains, &allowedPaths, &excludedPaths, &allowedPortsInt32,
		&t.MaxRPS, &label, &environment, &notes, &authConfigID,
		&createdAt, &updatedAt, &verifiedAt,
	)
	if err != nil {
		return err
	}
	t.AllowedPaths = allowedPaths
	t.ExcludedPaths = excludedPaths
	t.AllowedPorts = allowedPortsInt32
	t.CreatedAt = createdAt.Format(time.RFC3339)
	t.UpdatedAt = updatedAt.Format(time.RFC3339)
	if label != nil {
		t.Label = *label
	}
	if environment != nil {
		t.Environment = *environment
	}
	if notes != nil {
		t.Notes = *notes
	}
	if authConfigID != nil {
		t.AuthConfigID = *authConfigID
	}
	if verifiedAt != nil {
		v := verifiedAt.Format(time.RFC3339)
		t.VerifiedAt = &v
		t.VerificationStatus = "verified"
	} else {
		t.VerificationStatus = "pending"
	}
	return nil
}

const scanTargetColumns = `id, project_id, target_type, base_url,
	allowed_domains, allowed_paths, excluded_paths, allowed_ports,
	max_rps, label, environment, notes, auth_config_id::text,
	created_at, updated_at, verified_at`

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

	var req scanTargetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.TargetType == "" || req.BaseURL == "" {
		writeError(w, http.StatusBadRequest, "target_type and base_url are required", "BAD_REQUEST")
		return
	}
	normalized, vErr := validateTargetRequest(&req)
	if vErr != "" {
		writeError(w, http.StatusBadRequest, vErr, "BAD_REQUEST")
		return
	}

	// Enforce project ownership / org isolation via RLS.
	var created scanTargetResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		// Confirm the project exists and is visible under RLS before inserting.
		var exists bool
		if qErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core.projects WHERE id = $1)`, projectID).Scan(&exists); qErr != nil {
			return qErr
		}
		if !exists {
			return errNotVisible
		}

		// Validate auth_config_id (if any) belongs to the same project.
		if normalized.AuthConfigID != "" {
			var apPid string
			if apErr := tx.QueryRow(ctx,
				`SELECT project_id::text FROM auth.auth_configs WHERE id = $1`, normalized.AuthConfigID,
			).Scan(&apPid); apErr != nil || apPid != projectID {
				return userError{code: http.StatusBadRequest, msg: "auth_config_id does not belong to this project"}
			}
		}

		id := uuid.New().String()
		row := tx.QueryRow(ctx,
			`INSERT INTO core.scan_targets (
				id, project_id, target_type, base_url,
				allowed_domains, allowed_paths, excluded_paths, allowed_ports,
				max_rps, label, environment, notes, auth_config_id,
				created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now(),now())
			RETURNING `+scanTargetColumns,
			id, projectID, normalized.TargetType, normalized.BaseURL,
			normalized.AllowedDomains, normalized.AllowedPaths, normalized.ExcludedPaths, normalized.AllowedPorts,
			*normalized.MaxRPS, nullIfEmpty(normalized.Label), nullIfEmpty(normalized.Environment), nullIfEmpty(normalized.Notes),
			nullIfEmpty(normalized.AuthConfigID),
		)
		return scanRowInto(row, &created)
	})
	if err != nil {
		if err == errNotVisible {
			writeError(w, http.StatusNotFound, "project not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("failed to create scan target")
		writeError(w, http.StatusInternalServerError, "failed to create scan target", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "target.create", "user", user.UserID, "scan_target", created.ID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, map[string]any{"scan_target": created})
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

	var targets []scanTargetResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx,
			`SELECT `+scanTargetColumns+`
			 FROM core.scan_targets
			 WHERE project_id = $1
			 ORDER BY created_at DESC`, projectID)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()
		for rows.Next() {
			var t scanTargetResponse
			if sErr := scanRowInto(rows, &t); sErr != nil {
				return sErr
			}
			targets = append(targets, t)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list scan targets")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if targets == nil {
		targets = []scanTargetResponse{}
	}
	// Emit both keys during the migration so older frontend builds keep working.
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_targets": targets,
		"targets":      targets,
	})
}

// GetScanTarget returns a single scan target by ID.
func (h *Handlers) GetScanTarget(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "targets.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	var t scanTargetResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+scanTargetColumns+` FROM core.scan_targets WHERE id = $1`, id)
		return scanRowInto(row, &t)
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "scan target not found", "NOT_FOUND")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan_target": t})
}

// UpdateScanTarget updates mutable fields on a scan target. Project and
// target_type are intentionally immutable; changing them should be a new target.
func (h *Handlers) UpdateScanTarget(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "targets.create") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	var raw map[string]json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	var updated scanTargetResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		// Load current row under RLS — ensures org/project visibility.
		var current scanTargetRequest
		var curMaxRPS int
		var curProjectID string
		qErr := tx.QueryRow(ctx,
			`SELECT project_id::text, target_type, base_url, allowed_domains, allowed_paths, excluded_paths, allowed_ports,
			        max_rps, COALESCE(label,''), COALESCE(environment,''), COALESCE(notes,''), COALESCE(auth_config_id::text,'')
			   FROM core.scan_targets WHERE id = $1`, id,
		).Scan(
			&curProjectID,
			&current.TargetType, &current.BaseURL, &current.AllowedDomains, &current.AllowedPaths,
			&current.ExcludedPaths, &current.AllowedPorts, &curMaxRPS,
			&current.Label, &current.Environment, &current.Notes, &current.AuthConfigID,
		)
		if qErr != nil {
			return qErr
		}
		current.MaxRPS = &curMaxRPS

		// Apply only the fields supplied in the PATCH payload.
		if v, ok := raw["base_url"]; ok {
			_ = json.Unmarshal(v, &current.BaseURL)
		}
		if v, ok := raw["allowed_domains"]; ok {
			_ = json.Unmarshal(v, &current.AllowedDomains)
		}
		if v, ok := raw["allowed_paths"]; ok {
			_ = json.Unmarshal(v, &current.AllowedPaths)
		}
		if v, ok := raw["excluded_paths"]; ok {
			_ = json.Unmarshal(v, &current.ExcludedPaths)
		}
		if v, ok := raw["allowed_ports"]; ok {
			_ = json.Unmarshal(v, &current.AllowedPorts)
		}
		if v, ok := raw["max_rps"]; ok {
			var n int
			if err := json.Unmarshal(v, &n); err == nil {
				current.MaxRPS = &n
			}
		}
		if v, ok := raw["label"]; ok {
			_ = json.Unmarshal(v, &current.Label)
		}
		if v, ok := raw["environment"]; ok {
			_ = json.Unmarshal(v, &current.Environment)
		}
		if v, ok := raw["notes"]; ok {
			_ = json.Unmarshal(v, &current.Notes)
		}
		// auth_config_id: accept "" to clear, a uuid string to attach.
		authConfigChanged := false
		if v, ok := raw["auth_config_id"]; ok {
			_ = json.Unmarshal(v, &current.AuthConfigID)
			authConfigChanged = true
		}

		normalized, vErr := validateTargetRequest(&current)
		if vErr != "" {
			return userError{code: http.StatusBadRequest, msg: vErr}
		}

		// If the caller is attaching an auth profile, verify it belongs to the
		// same project. Detaching ("") is always allowed.
		if authConfigChanged && normalized.AuthConfigID != "" {
			var apPid string
			if apErr := tx.QueryRow(ctx,
				`SELECT project_id::text FROM auth.auth_configs WHERE id = $1`, normalized.AuthConfigID,
			).Scan(&apPid); apErr != nil || apPid != curProjectID {
				return userError{code: http.StatusBadRequest, msg: "auth_config_id does not belong to this project"}
			}
		}

		row := tx.QueryRow(ctx,
			`UPDATE core.scan_targets SET
				base_url        = $2,
				allowed_domains = $3,
				allowed_paths   = $4,
				excluded_paths  = $5,
				allowed_ports   = $6,
				max_rps         = $7,
				label           = $8,
				environment     = $9,
				notes           = $10,
				auth_config_id  = $11::uuid,
				updated_at      = now()
			 WHERE id = $1
			 RETURNING `+scanTargetColumns,
			id, normalized.BaseURL, normalized.AllowedDomains, normalized.AllowedPaths,
			normalized.ExcludedPaths, normalized.AllowedPorts, *normalized.MaxRPS,
			nullIfEmpty(normalized.Label), nullIfEmpty(normalized.Environment), nullIfEmpty(normalized.Notes),
			nullIfEmpty(normalized.AuthConfigID),
		)
		return scanRowInto(row, &updated)
	})
	if err != nil {
		if ue, ok := err.(userError); ok {
			writeError(w, ue.code, ue.msg, "BAD_REQUEST")
			return
		}
		writeError(w, http.StatusNotFound, "scan target not found", "NOT_FOUND")
		return
	}

	h.emitAuditEvent(r.Context(), "target.update", "user", user.UserID, "scan_target", updated.ID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, map[string]any{"scan_target": updated})
}

// DeleteScanTarget removes a scan target. The DB enforces referential integrity
// — targets referenced by existing scans will fail to delete with a constraint
// error, which we surface as 409 Conflict.
func (h *Handlers) DeleteScanTarget(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "targets.create") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		tag, dErr := tx.Exec(ctx, `DELETE FROM core.scan_targets WHERE id = $1`, id)
		if dErr != nil {
			return dErr
		}
		if tag.RowsAffected() == 0 {
			return errNotVisible
		}
		return nil
	})
	if err != nil {
		if err == errNotVisible {
			writeError(w, http.StatusNotFound, "scan target not found", "NOT_FOUND")
			return
		}
		if strings.Contains(err.Error(), "violates foreign key") {
			writeError(w, http.StatusConflict, "scan target is referenced by existing scans", "CONFLICT")
			return
		}
		h.logger.Error().Err(err).Msg("failed to delete scan target")
		writeError(w, http.StatusInternalServerError, "failed to delete scan target", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "target.delete", "user", user.UserID, "scan_target", id, r.RemoteAddr, "success")
	w.WriteHeader(http.StatusNoContent)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
