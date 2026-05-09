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
//
// core.organizations has no RLS policy (platform-level table), so the
// tenant.Tx wrapper here is belt-and-braces: the real boundary is the
// RBAC capability check at the route ("organizations.manage").
func (h *Handlers) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
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

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO core.organizations (id, name, display_name, status, created_at, updated_at)
				 VALUES ($1, $2, $3, 'active', $4, $4)`,
				id, req.Name, req.DisplayName, now)
			return err
		})
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

// ListOrganizations lists all organizations visible to the caller.
// Platform-admin-only; RBAC gates at the route.
func (h *Handlers) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	var orgs []orgResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				`SELECT id, name, display_name, status, created_at FROM core.organizations ORDER BY created_at DESC`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var o orgResponse
				var createdAt time.Time
				if err := rows.Scan(&o.ID, &o.Name, &o.DisplayName, &o.Status, &createdAt); err != nil {
					return err
				}
				o.CreatedAt = createdAt.Format(time.RFC3339)
				orgs = append(orgs, o)
			}
			return rows.Err()
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list organizations")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
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
	id := r.PathValue("id")
	var o orgResponse
	var createdAt time.Time
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT id, name, display_name, status, created_at FROM core.organizations WHERE id = $1`, id,
			).Scan(&o.ID, &o.Name, &o.DisplayName, &o.Status, &createdAt)
		})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "organization not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("failed to get organization")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
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
	id := r.PathValue("id")

	var req struct {
		DisplayName *string `json:"display_name"`
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
					`UPDATE core.organizations SET display_name = $1, updated_at = now() WHERE id = $2`,
					*req.DisplayName, id); err != nil {
					return err
				}
			}
			if req.Status != nil {
				if _, err := tx.Exec(ctx,
					`UPDATE core.organizations SET status = $1, updated_at = now() WHERE id = $2`,
					*req.Status, id); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to update organization")
		writeError(w, http.StatusInternalServerError, "failed to update", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "org.update", "user", user.UserID, "organization", id, r.RemoteAddr, "success")

	// Return updated org
	h.GetOrganization(w, r)
}
