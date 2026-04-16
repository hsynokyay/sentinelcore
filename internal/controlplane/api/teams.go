package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

type createTeamRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type teamResponse struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
}

type addMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type memberResponse struct {
	TeamID  string `json:"team_id"`
	UserID  string `json:"user_id"`
	Role    string `json:"role"`
	AddedAt string `json:"added_at"`
}

// CreateTeam creates a team within an organization.
func (h *Handlers) CreateTeam(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	orgID := r.PathValue("org_id")

	var req createTeamRequest
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
		`INSERT INTO core.teams (id, org_id, name, display_name, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $5)`,
		id, orgID, req.Name, req.DisplayName, now,
	)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to create team")
		writeError(w, http.StatusInternalServerError, "failed to create team", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "team.create", "user", user.UserID, "team", id, r.RemoteAddr, "success")

	writeJSON(w, http.StatusCreated, teamResponse{
		ID:          id,
		OrgID:       orgID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		CreatedAt:   now.Format(time.RFC3339),
	})
}

// ListTeams lists teams in an organization.
func (h *Handlers) ListTeams(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	orgID := r.PathValue("org_id")

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, org_id, name, display_name, created_at FROM core.teams WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list teams")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	defer rows.Close()

	var teams []teamResponse
	for rows.Next() {
		var t teamResponse
		var createdAt time.Time
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.DisplayName, &createdAt); err != nil {
			h.logger.Error().Err(err).Msg("failed to scan team")
			writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
			return
		}
		t.CreatedAt = createdAt.Format(time.RFC3339)
		teams = append(teams, t)
	}

	if teams == nil {
		teams = []teamResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"teams": teams})
}

// AddTeamMember adds a member to a team.
func (h *Handlers) AddTeamMember(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	teamID := r.PathValue("id")

	var req addMemberRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.UserID == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "user_id and role are required", "BAD_REQUEST")
		return
	}

	now := time.Now().UTC()
	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO core.team_memberships (team_id, user_id, role, joined_at)
		 VALUES ($1, $2, $3, $4)`,
		teamID, req.UserID, req.Role, now,
	)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to add team member")
		writeError(w, http.StatusInternalServerError, "failed to add member", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "team.member_add", "user", user.UserID, "team", teamID, r.RemoteAddr, "success")

	writeJSON(w, http.StatusCreated, memberResponse{
		TeamID:  teamID,
		UserID:  req.UserID,
		Role:    req.Role,
		AddedAt: now.Format(time.RFC3339),
	})
}

// ListTeamMembers lists members of a team.
func (h *Handlers) ListTeamMembers(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	teamID := r.PathValue("id")

	rows, err := h.pool.Query(r.Context(),
		`SELECT team_id, user_id, role, joined_at FROM core.team_memberships WHERE team_id = $1`, teamID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list team members")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	defer rows.Close()

	var members []memberResponse
	for rows.Next() {
		var m memberResponse
		var addedAt time.Time
		if err := rows.Scan(&m.TeamID, &m.UserID, &m.Role, &addedAt); err != nil {
			h.logger.Error().Err(err).Msg("failed to scan member")
			writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
			return
		}
		m.AddedAt = addedAt.Format(time.RFC3339)
		members = append(members, m)
	}

	if members == nil {
		members = []memberResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}
