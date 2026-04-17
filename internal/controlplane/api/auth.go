package api

import (
	"context"
	"net/http"
	"time"

	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Login authenticates a user and returns JWT tokens.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required", "BAD_REQUEST")
		return
	}

	// Query user by email
	var userID, orgID, role, passwordHash string
	err := h.pool.QueryRow(r.Context(),
		`SELECT id, org_id, role, COALESCE(password_hash, '') FROM core.users WHERE email = $1 AND status = 'active'`,
		req.Email,
	).Scan(&userID, &orgID, &role, &passwordHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials", "INVALID_CREDENTIALS")
		return
	}

	// SSO-only users (NULL password_hash) cannot use the password path.
	// Return USE_SSO with the org's enabled provider slugs so the UI can
	// route them to /api/v1/auth/sso/{org}/{provider}/start.
	if passwordHash == "" {
		var providerSlugs []string
		if h.ssoProviders != nil {
			if providers, err := h.ssoProviders.ListEnabledForOrg(r.Context(), orgID); err == nil {
				providerSlugs = make([]string, 0, len(providers))
				for _, p := range providers {
					providerSlugs = append(providerSlugs, p.ProviderSlug)
				}
			}
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":     "use SSO to sign in",
			"code":      "USE_SSO",
			"providers": providerSlugs,
		})
		return
	}

	if !auth.VerifyPassword(passwordHash, req.Password) {
		h.emitAuditEvent(r.Context(), "auth.login_failed", "user", userID, "user", userID, r.RemoteAddr, "failure")
		writeError(w, http.StatusUnauthorized, "invalid credentials", "INVALID_CREDENTIALS")
		return
	}

	accessToken, accessJTI, err := h.jwtMgr.IssueAccessToken(userID, orgID, role)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to issue access token")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	refreshToken, _, err := h.jwtMgr.IssueRefreshToken(userID, orgID, role)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to issue refresh token")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	// Create session in Redis
	if err := h.sessions.CreateSession(r.Context(), accessJTI, userID, 15*time.Minute); err != nil {
		h.logger.Error().Err(err).Msg("failed to create session")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "auth.login", "user", userID, "user", userID, r.RemoteAddr, "success")

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900,
	})
}

// Refresh validates a refresh token and issues a new access token.
func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required", "BAD_REQUEST")
		return
	}

	claims, err := h.jwtMgr.ValidateToken(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token", "INVALID_TOKEN")
		return
	}

	accessToken, accessJTI, err := h.jwtMgr.IssueAccessToken(claims.Subject, claims.OrgID, claims.Role)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to issue access token")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if err := h.sessions.CreateSession(r.Context(), accessJTI, claims.Subject, 15*time.Minute); err != nil {
		h.logger.Error().Err(err).Msg("failed to create session")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   900,
	})
}

// Logout revokes the current session.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}

	if err := h.sessions.RevokeSession(r.Context(), user.JTI); err != nil {
		h.logger.Error().Err(err).Msg("failed to revoke session")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "auth.logout", "user", user.UserID, "user", user.UserID, r.RemoteAddr, "success")

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// emitAuditEvent is a helper to emit audit events, logging errors but not failing the request.
func (h *Handlers) emitAuditEvent(ctx context.Context, action, actorType, actorID, resourceType, resourceID, actorIP, result string) {
	if h.emitter == nil {
		return
	}
	err := h.emitter.Emit(ctx, audit.AuditEvent{
		ActorType:    actorType,
		ActorID:      actorID,
		ActorIP:      actorIP,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       result,
	})
	if err != nil {
		h.logger.Error().Err(err).Str("action", action).Msg("failed to emit audit event")
	}
}
