package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
	OrgID    string `json:"org_id"`
}

type userResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	Role      string `json:"role"`
	OrgID     string `json:"org_id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// CreateUser creates a new user. Requires users.manage (owner only).
func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Email == "" || req.Password == "" || req.FullName == "" {
		writeError(w, http.StatusBadRequest, "email, password, and full_name are required", "BAD_REQUEST")
		return
	}
	if req.Role == "" {
		req.Role = "security_engineer"
	}
	if req.OrgID == "" {
		req.OrgID = user.OrgID
	}

	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to hash password")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC()

	err = tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO core.users (id, org_id, email, full_name, password_hash, role, status, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $7)`,
				id, req.OrgID, req.Email, req.FullName, passwordHash, req.Role, now)
			return err
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to create user")
		writeError(w, http.StatusInternalServerError, "failed to create user", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "user.create", "user", user.UserID, "user", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusCreated, userResponse{
		ID:        id,
		Email:     req.Email,
		FullName:  req.FullName,
		Role:      req.Role,
		OrgID:     req.OrgID,
		Status:    "active",
		CreatedAt: now.Format(time.RFC3339),
	})
}

// ListUsers lists users. Requires users.read (owner, admin, auditor).
func (h *Handlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	var users []userResponse
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				`SELECT id, email, full_name, role, org_id, status, created_at FROM core.users ORDER BY created_at DESC`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var u userResponse
				var createdAt time.Time
				if err := rows.Scan(&u.ID, &u.Email, &u.FullName, &u.Role, &u.OrgID, &u.Status, &createdAt); err != nil {
					return err
				}
				u.CreatedAt = createdAt.Format(time.RFC3339)
				users = append(users, u)
			}
			return rows.Err()
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list users")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if users == nil {
		users = []userResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// GetCurrentUser returns the authenticated user's profile.
func (h *Handlers) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}

	var u userResponse
	var createdAt time.Time
	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT id, email, display_name, role, org_id, status, created_at FROM core.users WHERE id = $1`,
				user.UserID,
			).Scan(&u.ID, &u.Email, &u.FullName, &u.Role, &u.OrgID, &u.Status, &createdAt)
		})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "user not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("failed to get current user")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	u.CreatedAt = createdAt.Format(time.RFC3339)

	writeJSON(w, http.StatusOK, u)
}
