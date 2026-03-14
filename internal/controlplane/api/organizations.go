package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

type createOrgRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type orgResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// CreateOrganization creates a new organization.
func (h *Handlers) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "orgs.create") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var req createOrgRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required", "BAD_REQUEST")
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Name
	}

	id := uuid.New().String()
	now := time.Now().UTC()

	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO core.organizations (id, name, display_name, status, created_at, updated_at)
		 VALUES ($1, $2, $3, 'active', $4, $4)`,
		id, req.Name, req.DisplayName, now,
	)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to create organization")
		writeError(w, http.StatusInternalServerError, "failed to create organization", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "org.create", "user", user.UserID, "organization", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusCreated, orgResponse{
		ID:          id,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Status:      "active",
		CreatedAt:   now.Format(time.RFC3339),
	})
}

// ListOrganizations lists all organizations.
func (h *Handlers) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "orgs.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, name, display_name, status, created_at FROM core.organizations ORDER BY created_at DESC`)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list organizations")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	defer rows.Close()

	var orgs []orgResponse
	for rows.Next() {
		var o orgResponse
		var createdAt time.Time
		if err := rows.Scan(&o.ID, &o.Name, &o.DisplayName, &o.Status, &createdAt); err != nil {
			h.logger.Error().Err(err).Msg("failed to scan organization")
			writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
			return
		}
		o.CreatedAt = createdAt.Format(time.RFC3339)
		orgs = append(orgs, o)
	}

	if orgs == nil {
		orgs = []orgResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"organizations": orgs})
}

// GetOrganization gets a single organization by ID.
func (h *Handlers) GetOrganization(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "orgs.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")
	var o orgResponse
	var createdAt time.Time
	err := h.pool.QueryRow(r.Context(),
		`SELECT id, name, display_name, status, created_at FROM core.organizations WHERE id = $1`, id,
	).Scan(&o.ID, &o.Name, &o.DisplayName, &o.Status, &createdAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "organization not found", "NOT_FOUND")
		return
	}
	o.CreatedAt = createdAt.Format(time.RFC3339)

	writeJSON(w, http.StatusOK, o)
}

// UpdateOrganization updates an organization.
func (h *Handlers) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "orgs.update") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	var req struct {
		DisplayName *string `json:"display_name"`
		Status      *string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	if req.DisplayName != nil {
		_, err := h.pool.Exec(r.Context(),
			`UPDATE core.organizations SET display_name = $1, updated_at = now() WHERE id = $2`,
			*req.DisplayName, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update", "INTERNAL_ERROR")
			return
		}
	}
	if req.Status != nil {
		_, err := h.pool.Exec(r.Context(),
			`UPDATE core.organizations SET status = $1, updated_at = now() WHERE id = $2`,
			*req.Status, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update", "INTERNAL_ERROR")
			return
		}
	}

	h.emitAuditEvent(r.Context(), "org.update", "user", user.UserID, "organization", id, r.RemoteAddr, "success")

	// Return updated org
	h.GetOrganization(w, r)
}
