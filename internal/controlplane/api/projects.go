package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

type createProjectRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	TeamID      string `json:"team_id"`
	Description string `json:"description"`
}

type projectResponse struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	TeamID      string `json:"team_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// CreateProject creates a new project.
func (h *Handlers) CreateProject(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	var req createProjectRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Name == "" || req.TeamID == "" {
		writeError(w, http.StatusBadRequest, "name and team_id are required", "BAD_REQUEST")
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Name
	}

	id := uuid.New().String()
	now := time.Now().UTC()

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO core.projects (id, org_id, team_id, name, display_name, description, status, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $7)`,
				id, user.OrgID, req.TeamID, req.Name, req.DisplayName, req.Description, now)
			return err
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to create project")
		writeError(w, http.StatusInternalServerError, "failed to create project", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "project.create", "user", user.UserID, "project", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusCreated, projectResponse{
		ID:          id,
		OrgID:       user.OrgID,
		TeamID:      req.TeamID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Status:      "active",
		CreatedAt:   now.Format(time.RFC3339),
	})
}

// ListProjects lists projects with RLS enforcement.
func (h *Handlers) ListProjects(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	var projects []projectResponse

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				`SELECT id, org_id, team_id, name, display_name, COALESCE(description, ''), status, created_at
				 FROM core.projects ORDER BY created_at DESC`)
			if err != nil {
				return err
			}
			defer rows.Close()

			for rows.Next() {
				var p projectResponse
				var createdAt time.Time
				if err := rows.Scan(&p.ID, &p.OrgID, &p.TeamID, &p.Name, &p.DisplayName, &p.Description, &p.Status, &createdAt); err != nil {
					return err
				}
				p.CreatedAt = createdAt.Format(time.RFC3339)
				projects = append(projects, p)
			}
			return rows.Err()
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list projects")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if projects == nil {
		projects = []projectResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
}

// GetProject gets a project by ID.
func (h *Handlers) GetProject(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	id := r.PathValue("id")
	var p projectResponse
	var createdAt time.Time
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT id, org_id, team_id, name, display_name, COALESCE(description, ''), status, created_at
				 FROM core.projects WHERE id = $1`, id,
			).Scan(&p.ID, &p.OrgID, &p.TeamID, &p.Name, &p.DisplayName, &p.Description, &p.Status, &createdAt)
		})
	if err != nil {
		// Both "belongs to other tenant" (filtered by RLS) and
		// "doesn't exist" collapse to 404 here, on purpose — see
		// tenant.ErrNotVisible rationale.
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "project not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("failed to get project")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	p.CreatedAt = createdAt.Format(time.RFC3339)

	writeJSON(w, http.StatusOK, p)
}

// UpdateProject updates a project.
func (h *Handlers) UpdateProject(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	id := r.PathValue("id")

	var req struct {
		DisplayName *string `json:"display_name"`
		Description *string `json:"description"`
		Status      *string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			if req.DisplayName != nil {
				if _, err := tx.Exec(ctx,
					`UPDATE core.projects SET display_name = $1, updated_at = now() WHERE id = $2`,
					*req.DisplayName, id); err != nil {
					return err
				}
			}
			if req.Description != nil {
				if _, err := tx.Exec(ctx,
					`UPDATE core.projects SET description = $1, updated_at = now() WHERE id = $2`,
					*req.Description, id); err != nil {
					return err
				}
			}
			if req.Status != nil {
				if _, err := tx.Exec(ctx,
					`UPDATE core.projects SET status = $1, updated_at = now() WHERE id = $2`,
					*req.Status, id); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to update project")
		writeError(w, http.StatusInternalServerError, "failed to update", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "project.update", "user", user.UserID, "project", id, r.RemoteAddr, "success")

	// Return updated project
	h.GetProject(w, r)
}
