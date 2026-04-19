package api

// Auth profile CRUD for DAST scans.
//
// Security contract (Chunk 2):
//   - Secret material (bearer token, api key, basic auth password) is only
//     accepted on the wire via create/update requests and is NEVER returned
//     from any endpoint. Stored as AES-256-GCM ciphertext in
//     auth.auth_configs.encrypted_secret, keyed by AUTH_PROFILE_ENCRYPTION_KEY.
//   - The `config` JSONB column only stores non-sensitive metadata (header
//     name, token prefix, endpoint URL, username, etc.). Responses surface
//     only those metadata fields plus a has_credentials boolean.
//   - Tenancy is enforced via RLS on auth.auth_configs (migration 017).
//   - Any endpoint URL (e.g. form-login URL, OAuth token URL) is run through
//     the existing SSRF-safe IP blocker (scope.IsBlockedIP) to prevent an
//     operator from pointing a scanner credential endpoint at cloud metadata
//     IPs or RFC1918 internals.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/crypto"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// validAuthProfileTypes enumerates the auth types Chunk 2 supports. Other
// values in the DB CHECK constraint (oauth2_*, form_login, etc.) are accepted
// schema-only and surfaced as "coming soon" in the UI.
var validAuthProfileTypes = map[string]bool{
	"bearer_token": true,
	"api_key":      true,
	"basic_auth":   true,
}

// authProfileCipher is lazily initialized from AUTH_PROFILE_ENCRYPTION_KEY.
var (
	authCipher     *crypto.AESGCM
	authCipherOnce sync.Once
	authCipherErr  error
)

func getAuthProfileCipher() (*crypto.AESGCM, error) {
	authCipherOnce.Do(func() {
		keyHex := os.Getenv("AUTH_PROFILE_ENCRYPTION_KEY")
		if keyHex == "" {
			authCipherErr = errors.New("AUTH_PROFILE_ENCRYPTION_KEY is not set")
			return
		}
		key, err := crypto.DecodeHexKey(keyHex)
		if err != nil {
			authCipherErr = fmt.Errorf("AUTH_PROFILE_ENCRYPTION_KEY invalid: %w", err)
			return
		}
		c, err := crypto.NewAESGCM(key)
		if err != nil {
			authCipherErr = err
			return
		}
		authCipher = c
	})
	return authCipher, authCipherErr
}

type authProfileRequest struct {
	Name        string `json:"name"`
	AuthType    string `json:"auth_type"`
	Description string `json:"description,omitempty"`

	// bearer_token fields
	Token       string `json:"token,omitempty"`        // write-only
	TokenPrefix string `json:"token_prefix,omitempty"` // e.g. "Bearer", default "Bearer"

	// api_key fields
	APIKey     string `json:"api_key,omitempty"`     // write-only
	HeaderName string `json:"header_name,omitempty"` // e.g. "X-API-Key"
	QueryName  string `json:"query_name,omitempty"`  // if the key goes in a query param

	// basic_auth fields
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"` // write-only

	// Optional endpoint URL (e.g. login URL) — validated for SSRF.
	EndpointURL string `json:"endpoint_url,omitempty"`
}

type authProfileResponse struct {
	ID             string         `json:"id"`
	ProjectID      string         `json:"project_id"`
	Name           string         `json:"name"`
	AuthType       string         `json:"auth_type"`
	Description    string         `json:"description,omitempty"`
	Metadata       map[string]any `json:"metadata"`
	HasCredentials bool           `json:"has_credentials"`
	CreatedBy      string         `json:"created_by"`
	CreatedAt      string         `json:"created_at"`
	UpdatedAt      string         `json:"updated_at"`
}

// buildMetadataAndSecret splits the incoming request into the public metadata
// map (stored in `config` jsonb) and the secret payload (stored in
// `encrypted_secret` bytea). The metadata map is what every GET response will
// return — it must never contain sensitive values.
func buildMetadataAndSecret(req *authProfileRequest) (metadata map[string]any, secret []byte, errMsg string) {
	metadata = map[string]any{}

	// Endpoint URL — run through the same SSRF-safe validator used by scope.
	if req.EndpointURL != "" {
		if e := validateSafeURL(req.EndpointURL); e != "" {
			return nil, nil, e
		}
		metadata["endpoint_url"] = req.EndpointURL
	}

	switch req.AuthType {
	case "bearer_token":
		if req.Token == "" {
			return nil, nil, "token is required for bearer_token"
		}
		prefix := strings.TrimSpace(req.TokenPrefix)
		if prefix == "" {
			prefix = "Bearer"
		}
		metadata["token_prefix"] = prefix
		secret = []byte(req.Token)
	case "api_key":
		if req.APIKey == "" {
			return nil, nil, "api_key is required for api_key"
		}
		// Placement: header by default, query if explicitly asked.
		header := req.HeaderName
		query := req.QueryName
		if header == "" && query == "" {
			header = "X-API-Key"
		}
		if header != "" && query != "" {
			return nil, nil, "specify either header_name or query_name, not both"
		}
		if header != "" {
			metadata["header_name"] = header
		}
		if query != "" {
			metadata["query_name"] = query
		}
		secret = []byte(req.APIKey)
	case "basic_auth":
		if req.Username == "" || req.Password == "" {
			return nil, nil, "username and password are required for basic_auth"
		}
		metadata["username"] = req.Username
		// Store password alone; username is metadata (not secret).
		secret = []byte(req.Password)
	default:
		return nil, nil, "auth_type must be one of: bearer_token, api_key, basic_auth"
	}
	return metadata, secret, ""
}

// validateSafeURL rejects URLs with invalid schemes or that resolve to
// blocked IP ranges (RFC1918, loopback, link-local, metadata IPs). This is the
// same policy used by the scan scope enforcer — we reuse it here so credential
// endpoints can't be pointed at internal infrastructure.
func validateSafeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "endpoint_url must be an absolute URL"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "endpoint_url scheme must be http or https"
	}
	// If the host is a literal IP, check it directly.
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if scope.IsBlockedIP(ip) {
			return "endpoint_url resolves to a blocked IP range"
		}
	}
	// NOTE: we deliberately do not do a live DNS lookup here — that happens at
	// scan dispatch time by the scope enforcer, which is TOCTOU-safe. At CRUD
	// time we only block obviously unsafe literal IPs.
	return ""
}

func (h *Handlers) encryptSecret(secret []byte, projectID string) ([]byte, error) {
	c, err := getAuthProfileCipher()
	if err != nil {
		return nil, err
	}
	// Bind ciphertext to project_id so a leaked blob can't be moved to another
	// project's row.
	return c.Seal(secret, []byte(projectID))
}

// rowToProfileResponse converts an auth_configs row into the public response
// shape. It strips the encrypted payload and sets has_credentials based on
// whether any secret was stored.
func rowToProfileResponse(
	id, projectID, name, authType, description, createdBy string,
	configJSON []byte, hasSecret bool, createdAt, updatedAt time.Time,
) authProfileResponse {
	var metadata map[string]any
	if len(configJSON) > 0 {
		_ = json.Unmarshal(configJSON, &metadata)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	return authProfileResponse{
		ID:             id,
		ProjectID:      projectID,
		Name:           name,
		AuthType:       authType,
		Description:    description,
		Metadata:       metadata,
		HasCredentials: hasSecret,
		CreatedBy:      createdBy,
		CreatedAt:      createdAt.Format(time.RFC3339),
		UpdatedAt:      updatedAt.Format(time.RFC3339),
	}
}

// CreateAuthProfile creates a new DAST auth profile for a project.
// POST /api/v1/projects/{id}/auth-profiles
func (h *Handlers) CreateAuthProfile(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "authprofiles.create") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.PathValue("id")

	var req authProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required", "BAD_REQUEST")
		return
	}
	if !validAuthProfileTypes[req.AuthType] {
		writeError(w, http.StatusBadRequest, "auth_type must be one of: bearer_token, api_key, basic_auth", "BAD_REQUEST")
		return
	}
	metadata, secret, errMsg := buildMetadataAndSecret(&req)
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg, "BAD_REQUEST")
		return
	}

	ciphertext, err := h.encryptSecret(secret, projectID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to encrypt auth profile secret")
		writeError(w, http.StatusInternalServerError, "failed to encrypt secret", "INTERNAL_ERROR")
		return
	}
	metaJSON, _ := json.Marshal(metadata)

	id := uuid.New().String()
	var created authProfileResponse
	err = tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		// Project visibility check under RLS.
		var exists bool
		if qErr := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM core.projects WHERE id = $1)`, projectID,
		).Scan(&exists); qErr != nil {
			return qErr
		}
		if !exists {
			return errNotVisible
		}

		var createdAt, updatedAt time.Time
		var createdBy string
		if insErr := tx.QueryRow(ctx,
			`INSERT INTO auth.auth_configs
			   (id, project_id, name, auth_type, description, config, encrypted_secret, created_by, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())
			 RETURNING created_by::text, created_at, updated_at`,
			id, projectID, req.Name, req.AuthType, nullIfEmpty(req.Description), metaJSON, ciphertext, user.UserID,
		).Scan(&createdBy, &createdAt, &updatedAt); insErr != nil {
			return insErr
		}

		created = rowToProfileResponse(
			id, projectID, req.Name, req.AuthType, req.Description, createdBy,
			metaJSON, len(ciphertext) > 0, createdAt, updatedAt,
		)
		return nil
	})
	if err != nil {
		if err == errNotVisible {
			writeError(w, http.StatusNotFound, "project not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("failed to create auth profile")
		writeError(w, http.StatusInternalServerError, "failed to create auth profile", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "authprofile.create", "user", user.UserID, "auth_profile", id, r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, map[string]any{"auth_profile": created})
}

// ListAuthProfiles returns all auth profiles for a project (metadata only).
// GET /api/v1/projects/{id}/auth-profiles
func (h *Handlers) ListAuthProfiles(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "authprofiles.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	projectID := r.PathValue("id")
	var profiles []authProfileResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx,
			`SELECT id, project_id, name, auth_type, COALESCE(description, ''),
			        COALESCE(config, '{}'::jsonb),
			        (encrypted_secret IS NOT NULL AND octet_length(encrypted_secret) > 0) AS has_secret,
			        created_by::text, created_at, updated_at
			   FROM auth.auth_configs
			  WHERE project_id = $1
			  ORDER BY created_at DESC`, projectID)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()
		for rows.Next() {
			var id, pid, name, authType, description, createdBy string
			var configJSON []byte
			var hasSecret bool
			var createdAt, updatedAt time.Time
			if sErr := rows.Scan(&id, &pid, &name, &authType, &description, &configJSON, &hasSecret, &createdBy, &createdAt, &updatedAt); sErr != nil {
				return sErr
			}
			profiles = append(profiles, rowToProfileResponse(id, pid, name, authType, description, createdBy, configJSON, hasSecret, createdAt, updatedAt))
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list auth profiles")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	if profiles == nil {
		profiles = []authProfileResponse{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_profiles": profiles})
}

// GetAuthProfile returns a single auth profile (metadata only).
// GET /api/v1/auth-profiles/{id}
func (h *Handlers) GetAuthProfile(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "authprofiles.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	id := r.PathValue("id")

	var profile authProfileResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		var pid, name, authType, description, createdBy string
		var configJSON []byte
		var hasSecret bool
		var createdAt, updatedAt time.Time
		qErr := tx.QueryRow(ctx,
			`SELECT project_id, name, auth_type, COALESCE(description,''),
			        COALESCE(config,'{}'::jsonb),
			        (encrypted_secret IS NOT NULL AND octet_length(encrypted_secret) > 0),
			        created_by::text, created_at, updated_at
			   FROM auth.auth_configs WHERE id = $1`, id,
		).Scan(&pid, &name, &authType, &description, &configJSON, &hasSecret, &createdBy, &createdAt, &updatedAt)
		if qErr != nil {
			return qErr
		}
		profile = rowToProfileResponse(id, pid, name, authType, description, createdBy, configJSON, hasSecret, createdAt, updatedAt)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "auth profile not found", "NOT_FOUND")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_profile": profile})
}

// UpdateAuthProfile updates metadata and/or rotates the secret on an existing
// auth profile. Secret fields left blank on a PATCH are NOT cleared — the
// existing encrypted_secret is preserved (write-only-rotate semantics).
// PATCH /api/v1/auth-profiles/{id}
func (h *Handlers) UpdateAuthProfile(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "authprofiles.create") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	id := r.PathValue("id")

	var req authProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	var updated authProfileResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		// Load current row (under RLS).
		var pid, curName, curAuthType, curDesc string
		var curConfig []byte
		qErr := tx.QueryRow(ctx,
			`SELECT project_id, name, auth_type, COALESCE(description,''), COALESCE(config,'{}'::jsonb)
			   FROM auth.auth_configs WHERE id = $1`, id,
		).Scan(&pid, &curName, &curAuthType, &curDesc, &curConfig)
		if qErr != nil {
			return qErr
		}

		// auth_type is immutable (would change secret shape).
		authType := curAuthType

		// Merge metadata/secret from request.
		// If caller sent any secret field, rotate. Otherwise preserve.
		rotating := false
		switch authType {
		case "bearer_token":
			rotating = req.Token != ""
		case "api_key":
			rotating = req.APIKey != ""
		case "basic_auth":
			rotating = req.Password != ""
		}

		name := curName
		if req.Name != "" {
			name = req.Name
		}
		description := curDesc
		if req.Description != "" {
			description = req.Description
		}

		var newConfigJSON []byte
		var newCiphertext []byte
		if rotating {
			// Build a full request using the CURRENT auth_type so validation passes.
			req.AuthType = authType
			metadata, secret, errMsg := buildMetadataAndSecret(&req)
			if errMsg != "" {
				return userError{code: http.StatusBadRequest, msg: errMsg}
			}
			newConfigJSON, _ = json.Marshal(metadata)
			ct, encErr := h.encryptSecret(secret, pid)
			if encErr != nil {
				return encErr
			}
			newCiphertext = ct
		} else {
			// Allow updating endpoint_url / header_name / token_prefix / username
			// without rotating the secret.
			var curMeta map[string]any
			_ = json.Unmarshal(curConfig, &curMeta)
			if curMeta == nil {
				curMeta = map[string]any{}
			}
			if req.EndpointURL != "" {
				if e := validateSafeURL(req.EndpointURL); e != "" {
					return userError{code: http.StatusBadRequest, msg: e}
				}
				curMeta["endpoint_url"] = req.EndpointURL
			}
			if req.TokenPrefix != "" && authType == "bearer_token" {
				curMeta["token_prefix"] = req.TokenPrefix
			}
			if req.HeaderName != "" && authType == "api_key" {
				curMeta["header_name"] = req.HeaderName
				delete(curMeta, "query_name")
			}
			if req.QueryName != "" && authType == "api_key" {
				curMeta["query_name"] = req.QueryName
				delete(curMeta, "header_name")
			}
			if req.Username != "" && authType == "basic_auth" {
				curMeta["username"] = req.Username
			}
			newConfigJSON, _ = json.Marshal(curMeta)
		}

		// UPDATE — only overwrite encrypted_secret when rotating.
		var createdAt, updatedAt time.Time
		var createdBy string
		var hasSecret bool
		if rotating {
			err2 := tx.QueryRow(ctx,
				`UPDATE auth.auth_configs SET
				    name = $2, description = $3, config = $4, encrypted_secret = $5, updated_at = now()
				  WHERE id = $1
				  RETURNING created_by::text, created_at, updated_at,
				            (encrypted_secret IS NOT NULL AND octet_length(encrypted_secret) > 0)`,
				id, name, nullIfEmpty(description), newConfigJSON, newCiphertext,
			).Scan(&createdBy, &createdAt, &updatedAt, &hasSecret)
			if err2 != nil {
				return err2
			}
		} else {
			err2 := tx.QueryRow(ctx,
				`UPDATE auth.auth_configs SET
				    name = $2, description = $3, config = $4, updated_at = now()
				  WHERE id = $1
				  RETURNING created_by::text, created_at, updated_at,
				            (encrypted_secret IS NOT NULL AND octet_length(encrypted_secret) > 0)`,
				id, name, nullIfEmpty(description), newConfigJSON,
			).Scan(&createdBy, &createdAt, &updatedAt, &hasSecret)
			if err2 != nil {
				return err2
			}
		}

		updated = rowToProfileResponse(id, pid, name, authType, description, createdBy, newConfigJSON, hasSecret, createdAt, updatedAt)
		return nil
	})
	if err != nil {
		if ue, ok := err.(userError); ok {
			writeError(w, ue.code, ue.msg, "BAD_REQUEST")
			return
		}
		writeError(w, http.StatusNotFound, "auth profile not found", "NOT_FOUND")
		return
	}

	h.emitAuditEvent(r.Context(), "authprofile.update", "user", user.UserID, "auth_profile", id, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, map[string]any{"auth_profile": updated})
}

// DeleteAuthProfile removes an auth profile.
// DELETE /api/v1/auth-profiles/{id}
func (h *Handlers) DeleteAuthProfile(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "authprofiles.delete") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	id := r.PathValue("id")

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		tag, dErr := tx.Exec(ctx, `DELETE FROM auth.auth_configs WHERE id = $1`, id)
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
			writeError(w, http.StatusNotFound, "auth profile not found", "NOT_FOUND")
			return
		}
		if strings.Contains(err.Error(), "violates foreign key") {
			writeError(w, http.StatusConflict, "auth profile is referenced by existing scan targets", "CONFLICT")
			return
		}
		h.logger.Error().Err(err).Msg("failed to delete auth profile")
		writeError(w, http.StatusInternalServerError, "failed to delete auth profile", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "authprofile.delete", "user", user.UserID, "auth_profile", id, r.RemoteAddr, "success")
	w.WriteHeader(http.StatusNoContent)
}
