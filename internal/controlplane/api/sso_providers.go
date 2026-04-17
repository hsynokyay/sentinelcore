package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/sso"
)

// providerJSON is the wire format. Reads NEVER include client_secret.
// Writes carry it only on create or explicit rotation.
type providerJSON struct {
	ID               string   `json:"id,omitempty"`
	ProviderSlug     string   `json:"provider_slug"`
	DisplayName      string   `json:"display_name"`
	IssuerURL        string   `json:"issuer_url"`
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret,omitempty"` // write-only
	Scopes           []string `json:"scopes"`
	DefaultRoleID    string   `json:"default_role_id"`
	SyncRoleOnLogin  bool     `json:"sync_role_on_login"`
	SSOLogoutEnabled bool     `json:"sso_logout_enabled"`
	EndSessionURL    string   `json:"end_session_url,omitempty"` // read-only
	Enabled          bool     `json:"enabled"`
	HasSecret        bool     `json:"has_secret"` // signals "already set"
}

func toProviderJSON(p sso.Provider) providerJSON {
	return providerJSON{
		ID:               p.ID,
		ProviderSlug:     p.ProviderSlug,
		DisplayName:      p.DisplayName,
		IssuerURL:        p.IssuerURL,
		ClientID:         p.ClientID,
		Scopes:           p.Scopes,
		DefaultRoleID:    p.DefaultRoleID,
		SyncRoleOnLogin:  p.SyncRoleOnLogin,
		SSOLogoutEnabled: p.SSOLogoutEnabled,
		EndSessionURL:    p.EndSessionURL,
		Enabled:          p.Enabled,
		HasSecret:        true,
	}
}

// ListSSOProviders handles GET /api/v1/sso/providers — sso.manage.
func (h *Handlers) ListSSOProviders(w http.ResponseWriter, r *http.Request) {
	if h.ssoProviders == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	providers, err := h.ssoProviders.List(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("list sso providers")
		writeError(w, http.StatusInternalServerError, "failed to list providers", "INTERNAL")
		return
	}
	out := make([]providerJSON, 0, len(providers))
	for _, p := range providers {
		out = append(out, toProviderJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

// CreateSSOProvider handles POST /api/v1/sso/providers — sso.manage.
func (h *Handlers) CreateSSOProvider(w http.ResponseWriter, r *http.Request) {
	if h.ssoProviders == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	var req providerJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", "BAD_REQUEST")
		return
	}
	defer r.Body.Close()
	if req.ProviderSlug == "" || req.DisplayName == "" || req.IssuerURL == "" ||
		req.ClientID == "" || req.ClientSecret == "" || req.DefaultRoleID == "" {
		writeError(w, http.StatusBadRequest, "missing required field", "BAD_REQUEST")
		return
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "email", "profile", "groups"}
	}
	prov := sso.Provider{
		OrgID:            p.OrgID,
		ProviderSlug:     req.ProviderSlug,
		DisplayName:      req.DisplayName,
		IssuerURL:        req.IssuerURL,
		ClientID:         req.ClientID,
		ClientSecret:     req.ClientSecret,
		Scopes:           req.Scopes,
		DefaultRoleID:    req.DefaultRoleID,
		SyncRoleOnLogin:  req.SyncRoleOnLogin,
		SSOLogoutEnabled: req.SSOLogoutEnabled,
		Enabled:          req.Enabled,
	}
	id, err := h.ssoProviders.Create(r.Context(), prov)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}

	h.emitAuditSSO(r.Context(), p, "auth.sso.provider.create", id, map[string]any{
		"provider_slug": prov.ProviderSlug,
		"issuer_url":    prov.IssuerURL,
		"default_role":  prov.DefaultRoleID,
		"scopes":        prov.Scopes,
	})

	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// GetSSOProvider handles GET /api/v1/sso/providers/{id} — sso.manage.
func (h *Handlers) GetSSOProvider(w http.ResponseWriter, r *http.Request) {
	if h.ssoProviders == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	id := r.PathValue("id")
	p, err := h.ssoProviders.Get(r.Context(), id)
	if errors.Is(err, sso.ErrProviderNotFound) {
		writeError(w, http.StatusNotFound, "not found", "NOT_FOUND")
		return
	}
	if err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("get sso provider")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	writeJSON(w, http.StatusOK, toProviderJSON(p))
}

// UpdateSSOProvider handles PATCH /api/v1/sso/providers/{id} — sso.manage.
// Empty client_secret preserves the existing one.
func (h *Handlers) UpdateSSOProvider(w http.ResponseWriter, r *http.Request) {
	if h.ssoProviders == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	id := r.PathValue("id")
	var req providerJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", "BAD_REQUEST")
		return
	}
	defer r.Body.Close()

	current, err := h.ssoProviders.Get(r.Context(), id)
	if errors.Is(err, sso.ErrProviderNotFound) {
		writeError(w, http.StatusNotFound, "not found", "NOT_FOUND")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	merged := current
	if req.DisplayName != "" {
		merged.DisplayName = req.DisplayName
	}
	if req.IssuerURL != "" {
		merged.IssuerURL = req.IssuerURL
	}
	if req.ClientID != "" {
		merged.ClientID = req.ClientID
	}
	if len(req.Scopes) > 0 {
		merged.Scopes = req.Scopes
	}
	if req.DefaultRoleID != "" {
		merged.DefaultRoleID = req.DefaultRoleID
	}
	// Bools always sent in PATCH body (frontend contract).
	merged.SyncRoleOnLogin = req.SyncRoleOnLogin
	merged.SSOLogoutEnabled = req.SSOLogoutEnabled
	merged.Enabled = req.Enabled

	if err := h.ssoProviders.Update(r.Context(), id, merged, req.ClientSecret); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("update sso provider")
		writeError(w, http.StatusInternalServerError, "update failed", "INTERNAL")
		return
	}

	// Config changed → invalidate cached discovery client.
	if h.ssoClients != nil {
		h.ssoClients.Invalidate(id)
	}

	h.emitAuditSSO(r.Context(), principal, "auth.sso.provider.update", id, map[string]any{
		"provider_slug":      merged.ProviderSlug,
		"secret_rotated":     req.ClientSecret != "",
		"enabled":            merged.Enabled,
		"default_role":       merged.DefaultRoleID,
		"sync_role_on_login": merged.SyncRoleOnLogin,
		"sso_logout_enabled": merged.SSOLogoutEnabled,
	})

	w.WriteHeader(http.StatusNoContent)
}

// DeleteSSOProvider handles DELETE /api/v1/sso/providers/{id} — sso.manage.
func (h *Handlers) DeleteSSOProvider(w http.ResponseWriter, r *http.Request) {
	if h.ssoProviders == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	id := r.PathValue("id")
	if err := h.ssoProviders.Delete(r.Context(), id); err != nil {
		if errors.Is(err, sso.ErrProviderNotFound) {
			writeError(w, http.StatusNotFound, "not found", "NOT_FOUND")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	if h.ssoClients != nil {
		h.ssoClients.Invalidate(id)
	}

	h.emitAuditSSO(r.Context(), principal, "auth.sso.provider.delete", id, nil)

	w.WriteHeader(http.StatusNoContent)
}

// emitAuditSSO is the common audit-event emitter for SSO admin actions.
func (h *Handlers) emitAuditSSO(ctx context.Context, p auth.Principal, action, resourceID string, details map[string]any) {
	if h.emitter == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	if err := h.emitter.Emit(ctx, audit.AuditEvent{
		ActorType:    p.Kind,
		ActorID:      p.UserID,
		Action:       action,
		ResourceType: "sso_provider",
		ResourceID:   resourceID,
		OrgID:        p.OrgID,
		Result:       "success",
		Details:      details,
	}); err != nil {
		h.logger.Error().Err(err).Str("action", action).Msg("emit sso audit")
	}
}
