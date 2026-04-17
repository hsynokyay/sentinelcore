package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/sso"
	"github.com/sentinelcore/sentinelcore/pkg/ssostate"
)

// ============================================================================
// /start
// ============================================================================

// StartSSO handles GET /api/v1/auth/sso/{org}/{provider}/start — public.
// Generates state/nonce/PKCE, stashes in Redis for 5 min, redirects to IdP.
func (h *Handlers) StartSSO(w http.ResponseWriter, r *http.Request) {
	if h.ssoProviders == nil || h.ssoState == nil || h.ssoClients == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	orgSlug := r.PathValue("org")
	providerSlug := r.PathValue("provider")

	p, err := h.ssoProviders.GetByOrgSlug(r.Context(), orgSlug, providerSlug)
	if errors.Is(err, sso.ErrProviderNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.logger.Error().Err(err).Str("org", orgSlug).Str("provider", providerSlug).Msg("start sso provider lookup")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if !sso.ValidateReturnTo(returnTo) {
		returnTo = "/dashboard"
	}

	state, err := randomURLSafe(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rand failed", "INTERNAL")
		return
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rand failed", "INTERNAL")
		return
	}
	verifier, err := sso.GenerateVerifier()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rand failed", "INTERNAL")
		return
	}
	challenge := sso.ChallengeS256(verifier)

	if err := h.ssoState.Put(r.Context(), state, ssostate.State{
		OrgID:        p.OrgID,
		ProviderID:   p.ID,
		PKCEVerifier: verifier,
		Nonce:        nonce,
		ReturnTo:     returnTo,
		ExpiresAt:    time.Now().Add(ssostate.DefaultTTL),
	}); err != nil {
		h.logger.Error().Err(err).Msg("sso state put")
		writeError(w, http.StatusInternalServerError, "state store", "INTERNAL")
		return
	}

	redirectURL := h.ssoCallbackURL(r, orgSlug, providerSlug)
	client, err := h.ssoClients.GetOrCreate(r.Context(), p.ID, sso.Config{
		IssuerURL:    p.IssuerURL,
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       p.Scopes,
	})
	if err != nil {
		h.logger.Error().Err(err).Str("provider_id", p.ID).Msg("sso discovery")
		writeError(w, http.StatusBadGateway, "provider discovery failed", "BAD_GATEWAY")
		return
	}
	// Cache end_session_url for logout if we learned one.
	if es := client.EndSessionURL(); es != "" && p.EndSessionURL == "" {
		_ = h.ssoProviders.UpdateEndSessionURL(r.Context(), p.ID, es)
	}

	http.Redirect(w, r, client.AuthorizeURL(state, nonce, challenge), http.StatusFound)
}

// ============================================================================
// /callback
// ============================================================================

// SSOCallback handles GET /api/v1/auth/sso/{org}/{provider}/callback — public.
// Consumes state, exchanges code, verifies id_token, resolves/provisions user,
// mints session, redirects to stored return_to.
func (h *Handlers) SSOCallback(w http.ResponseWriter, r *http.Request) {
	if h.ssoProviders == nil || h.ssoState == nil || h.ssoClients == nil || h.ssoMappings == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	orgSlug := r.PathValue("org")
	providerSlug := r.PathValue("provider")
	stateTok := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// --- State consumption (single-use) ---
	stored, err := h.ssoState.Take(r.Context(), stateTok)
	if errors.Is(err, ssostate.ErrStateNotFound) {
		h.logSSOEvent(r, "", "callback_error", "state_not_found", nil, nil, nil)
		writeError(w, http.StatusBadRequest, "state invalid or expired", "BAD_REQUEST")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state take", "INTERNAL")
		return
	}

	// --- Cross-tenant replay guard ---
	var urlOrgID string
	err = h.pool.QueryRow(r.Context(),
		`SELECT id::text FROM core.organizations WHERE slug = $1`, orgSlug).
		Scan(&urlOrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		h.logSSOEvent(r, "", "callback_error", "org_not_found", nil, nil, nil)
		writeError(w, http.StatusBadRequest, "invalid callback", "BAD_REQUEST")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "org lookup", "INTERNAL")
		return
	}
	if stored.OrgID != urlOrgID {
		h.logSSOEvent(r, "", "callback_error", "state_org_mismatch", nil, nil, nil)
		writeError(w, http.StatusBadRequest, "invalid callback", "BAD_REQUEST")
		return
	}

	p, err := h.ssoProviders.Get(r.Context(), stored.ProviderID)
	if err != nil {
		h.logSSOEvent(r, stored.ProviderID, "callback_error", "provider_lookup_failed", nil, nil, nil)
		writeError(w, http.StatusInternalServerError, "provider lookup", "INTERNAL")
		return
	}
	if p.OrgID != urlOrgID || p.ProviderSlug != providerSlug {
		h.logSSOEvent(r, p.ID, "callback_error", "state_provider_mismatch", nil, nil, nil)
		writeError(w, http.StatusBadRequest, "invalid callback", "BAD_REQUEST")
		return
	}

	// --- Token exchange ---
	redirectURL := h.ssoCallbackURL(r, orgSlug, providerSlug)
	client, err := h.ssoClients.GetOrCreate(r.Context(), p.ID, sso.Config{
		IssuerURL:    p.IssuerURL,
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       p.Scopes,
	})
	if err != nil {
		h.logSSOEvent(r, p.ID, "callback_error", "discovery_failed", nil, nil, nil)
		writeError(w, http.StatusBadGateway, "provider discovery", "BAD_GATEWAY")
		return
	}
	rawIDToken, err := client.Exchange(r.Context(), code, stored.PKCEVerifier)
	if err != nil {
		h.logger.Warn().Err(err).Str("provider_id", p.ID).Msg("sso code exchange")
		h.logSSOEvent(r, p.ID, "callback_error", "code_exchange_failed", nil, nil, nil)
		writeError(w, http.StatusBadRequest, "code exchange failed", "BAD_REQUEST")
		return
	}

	// --- Verify id_token ---
	claims, err := client.VerifyIDToken(r.Context(), rawIDToken, stored.Nonce)
	if err != nil {
		ec := classifySSOVerifyError(err)
		h.logSSOEvent(r, p.ID, "claim_error", ec, nil, nil, nil)
		writeError(w, http.StatusBadRequest, "id_token verification failed", "BAD_REQUEST")
		return
	}
	if claims.Sub == "" || claims.Email == "" {
		h.logSSOEvent(r, p.ID, "claim_error", "missing_required_claim",
			&claims.Sub, &claims.Email, nil)
		writeError(w, http.StatusBadRequest, "id_token missing sub or email", "BAD_REQUEST")
		return
	}

	// --- Role resolution + JIT ---
	mappings, err := h.ssoMappings.ListForResolver(r.Context(), p.ID)
	if err != nil {
		h.logSSOEvent(r, p.ID, "user_error", "mapping_load_failed",
			&claims.Sub, &claims.Email, nil)
		writeError(w, http.StatusInternalServerError, "mapping load", "INTERNAL")
		return
	}
	resolvedRole, _ := sso.ResolveRole(claims.Groups, mappings, p.DefaultRoleID)

	userID, createdJIT, err := h.resolveOrProvisionSSOUser(r.Context(),
		p.OrgID, p.ProviderSlug, claims, resolvedRole, p.SyncRoleOnLogin)
	if err != nil {
		h.logger.Error().Err(err).Str("provider_id", p.ID).Str("external_id", claims.Sub).Msg("sso jit")
		h.logSSOEvent(r, p.ID, "user_error", "provision_failed",
			&claims.Sub, &claims.Email, &resolvedRole)
		writeError(w, http.StatusInternalServerError, "user provision failed", "INTERNAL")
		return
	}

	// --- Mint session ---
	accessToken, accessJTI, err := h.jwtMgr.IssueAccessToken(userID, p.OrgID, resolvedRole)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session issue", "INTERNAL")
		return
	}
	if err := h.sessions.CreateSession(r.Context(), accessJTI, userID, 15*time.Minute); err != nil {
		writeError(w, http.StatusInternalServerError, "session create", "INTERNAL")
		return
	}
	refreshToken, _, err := h.jwtMgr.IssueRefreshToken(userID, p.OrgID, resolvedRole)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "refresh issue", "INTERNAL")
		return
	}
	h.setSSOAuthCookies(w, r, accessToken, refreshToken)

	// --- Audit + diagnostics ---
	if h.emitter != nil {
		_ = h.emitter.Emit(r.Context(), audit.AuditEvent{
			ActorType:    "user",
			ActorID:      userID,
			ActorIP:      clientIP(r),
			Action:       "auth.sso.login",
			ResourceType: "user",
			ResourceID:   userID,
			OrgID:        p.OrgID,
			Result:       "success",
			Details: map[string]any{
				"provider_slug": p.ProviderSlug,
				"external_id":   claims.Sub,
				"jit_created":   createdJIT,
				"role_granted":  resolvedRole,
				"sync_role":     p.SyncRoleOnLogin,
			},
		})
	}
	h.logSSOEvent(r, p.ID, "success", "", &claims.Sub, &claims.Email, &resolvedRole)

	http.Redirect(w, r, stored.ReturnTo, http.StatusFound)
}

// classifySSOVerifyError maps sso package sentinel errors to the
// error_code column value in auth.sso_login_events.
func classifySSOVerifyError(err error) string {
	switch {
	case errors.Is(err, sso.ErrNonceMismatch):
		return "nonce_mismatch"
	case errors.Is(err, sso.ErrAudMismatch):
		return "aud_mismatch"
	case errors.Is(err, sso.ErrIssuerMismatch):
		return "iss_mismatch"
	case errors.Is(err, sso.ErrTokenExpired):
		return "token_expired"
	case errors.Is(err, sso.ErrClaimsMalformed):
		return "claims_malformed"
	default:
		return "verify_failed"
	}
}

// ============================================================================
// JIT provisioning
// ============================================================================

// resolveOrProvisionSSOUser runs the spec's 3-step lookup chain inside one tx:
//  1. (org_id, identity_provider, external_id) → found → optional role sync
//  2. (org_id, email) → attach SSO identity to existing local user
//  3. JIT INSERT … ON CONFLICT (org_id, email) DO UPDATE
//
// Returns (user_id, createdJIT=true if row was inserted, error).
func (h *Handlers) resolveOrProvisionSSOUser(
	ctx context.Context, orgID, providerSlug string,
	claims *sso.Claims, resolvedRole string, syncRole bool,
) (string, bool, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `SET LOCAL app.current_org_id = $1`, orgID); err != nil {
		return "", false, fmt.Errorf("set RLS context: %w", err)
	}

	// --- Step 1: by (org_id, identity_provider, external_id) ---
	var (
		id               string
		existingRole     string
		existingProvider string
		status           string
	)
	err = tx.QueryRow(ctx, `
		SELECT id::text, role, identity_provider, status FROM core.users
		WHERE org_id = $1 AND identity_provider = $2 AND external_id = $3
	`, orgID, providerSlug, claims.Sub).Scan(&id, &existingRole, &existingProvider, &status)
	switch {
	case err == nil:
		if status != "active" {
			return "", false, fmt.Errorf("user %s is %s", id, status)
		}
		if syncRole && existingRole != resolvedRole {
			if _, err := tx.Exec(ctx,
				`UPDATE core.users SET role = $1 WHERE id = $2`, resolvedRole, id); err != nil {
				return "", false, err
			}
		}
		return id, false, tx.Commit(ctx)
	case !errors.Is(err, pgx.ErrNoRows):
		return "", false, err
	}

	// --- Step 2: fallback by (org_id, email) ---
	err = tx.QueryRow(ctx, `
		SELECT id::text, role, identity_provider, status FROM core.users
		WHERE org_id = $1 AND email = $2
	`, orgID, claims.Email).Scan(&id, &existingRole, &existingProvider, &status)
	switch {
	case err == nil:
		if status != "active" {
			return "", false, fmt.Errorf("user %s is %s", id, status)
		}
		if existingProvider == "local" || existingProvider == "" {
			if _, err := tx.Exec(ctx,
				`UPDATE core.users SET identity_provider = $1, external_id = $2 WHERE id = $3`,
				providerSlug, claims.Sub, id); err != nil {
				return "", false, err
			}
		}
		if syncRole && existingRole != resolvedRole {
			if _, err := tx.Exec(ctx,
				`UPDATE core.users SET role = $1 WHERE id = $2`, resolvedRole, id); err != nil {
				return "", false, err
			}
		}
		return id, false, tx.Commit(ctx)
	case !errors.Is(err, pgx.ErrNoRows):
		return "", false, err
	}

	// --- Step 3: JIT insert ---
	// Deterministic username (base + sub-hash suffix) ensures concurrent
	// callbacks with identical claims.Sub derive identical usernames,
	// so the (org_id, email) ON CONFLICT path resolves the race without
	// colliding on the (org_id, username) unique constraint.
	username := deriveUsername(claims.Sub, claims.Email) + "-" + hashHex6(claims.Sub)
	displayName := claims.Name
	if displayName == "" {
		displayName = claims.Email
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO core.users (
		    org_id, username, email, display_name, role, status,
		    identity_provider, external_id, password_hash
		) VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, NULL)
		ON CONFLICT (org_id, email) DO UPDATE
		    SET identity_provider = EXCLUDED.identity_provider,
		        external_id       = EXCLUDED.external_id
		RETURNING id::text
	`, orgID, username, claims.Email, displayName, resolvedRole, providerSlug, claims.Sub).Scan(&id)
	if err != nil {
		return "", false, err
	}
	return id, true, tx.Commit(ctx)
}

// ============================================================================
// /auth/sso/enabled
// ============================================================================

// EnabledSSOProviders handles GET /api/v1/auth/sso/enabled?org=<slug> — public.
// Returns redacted provider list for the login page.
// Unknown org returns `{providers: []}` (same shape as known-with-none),
// so the endpoint cannot be used to enumerate org slugs.
func (h *Handlers) EnabledSSOProviders(w http.ResponseWriter, r *http.Request) {
	if h.ssoProviders == nil {
		writeJSON(w, http.StatusOK, map[string]any{"providers": []any{}})
		return
	}
	orgSlug := r.URL.Query().Get("org")
	if orgSlug == "" {
		writeError(w, http.StatusBadRequest, "missing org", "BAD_REQUEST")
		return
	}
	providers, err := h.ssoProviders.ListEnabledPublicByOrgSlug(r.Context(), orgSlug)
	if err != nil {
		h.logger.Error().Err(err).Str("org", orgSlug).Msg("list enabled sso")
		// fail closed: empty list, never reveal error detail pre-auth.
		writeJSON(w, http.StatusOK, map[string]any{"providers": []any{}})
		return
	}
	out := make([]map[string]any, 0, len(providers))
	for _, p := range providers {
		out = append(out, map[string]any{
			"provider_slug": p.ProviderSlug,
			"display_name":  p.DisplayName,
			"start_url":     "/api/v1/auth/sso/" + orgSlug + "/" + p.ProviderSlug + "/start",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

// ============================================================================
// /sso/logout
// ============================================================================

// SSOLogout handles POST /api/v1/auth/sso/logout — authenticated.
// Revokes the local session, clears cookies, and if the user is logged
// in via an SSO provider with SSOLogoutEnabled+EndSessionURL set, returns
// a redirect target for RP-Initiated Logout so the caller can 302 the
// browser to the IdP.
//
// Body: {"provider_id": "..."} — optional; omit to local-logout only.
func (h *Handlers) SSOLogout(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}

	var req struct {
		ProviderID string `json:"provider_id"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
		defer r.Body.Close()
	}

	// Local logout (best-effort — don't block IdP redirect on failure).
	if h.sessions != nil && principal.JTI != "" {
		if err := h.sessions.RevokeSession(r.Context(), principal.JTI); err != nil {
			h.logger.Warn().Err(err).Msg("sso logout: revoke session")
		}
	}
	h.clearSSOAuthCookies(w, r)

	if h.emitter != nil {
		_ = h.emitter.Emit(r.Context(), audit.AuditEvent{
			ActorType:    "user",
			ActorID:      principal.UserID,
			ActorIP:      clientIP(r),
			Action:       "auth.sso.logout",
			ResourceType: "user",
			ResourceID:   principal.UserID,
			OrgID:        principal.OrgID,
			Result:       "success",
			Details: map[string]any{
				"provider_id": req.ProviderID,
			},
		})
	}

	// If no provider hint, we're done.
	if req.ProviderID == "" || h.ssoProviders == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	p, err := h.ssoProviders.Get(r.Context(), req.ProviderID)
	if err != nil || !p.SSOLogoutEnabled || p.EndSessionURL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	// Build end_session URL. id_token_hint is required by some IdPs
	// (Keycloak, Azure AD). We don't currently stash the id_token on
	// session mint — adding that is a follow-up — so we emit a hintless
	// URL which works for Okta and any IdP that tolerates its absence.
	sep := "?"
	if strings.Contains(p.EndSessionURL, "?") {
		sep = "&"
	}
	redirect := p.EndSessionURL + sep + "post_logout_redirect_uri=" +
		strings.TrimRight(h.publicBaseURL, "/") + "/login"
	writeJSON(w, http.StatusOK, map[string]any{"redirect": redirect})
}

// clearSSOAuthCookies expires the cookies set by setSSOAuthCookies.
func (h *Handlers) clearSSOAuthCookies(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	for _, name := range []string{"sc_access_token", "sc_refresh_token"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

// ============================================================================
// Helpers
// ============================================================================

// ssoCallbackURL constructs the absolute callback URL for a given
// org/provider pair. Prefers h.publicBaseURL; falls back to the
// request's scheme+host (works for single-origin deployments).
func (h *Handlers) ssoCallbackURL(r *http.Request, orgSlug, providerSlug string) string {
	base := strings.TrimRight(h.publicBaseURL, "/")
	if base == "" {
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
			scheme = "http"
		} else if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
			scheme = xf
		}
		base = scheme + "://" + r.Host
	}
	return base + "/api/v1/auth/sso/" + orgSlug + "/" + providerSlug + "/callback"
}

// setSSOAuthCookies writes HTTP-only Secure cookies so the browser
// carries the session across the final 302 back to return_to. We set
// BOTH access and refresh cookies (matching the existing JSON response
// contract for password login) so the frontend's normal refresh flow
// continues to work after an SSO login.
func (h *Handlers) setSSOAuthCookies(w http.ResponseWriter, r *http.Request, access, refresh string) {
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     "sc_access_token",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   900,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "sc_refresh_token",
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 3600,
	})
}

// logSSOEvent writes an operational diagnostic row into
// auth.sso_login_events. Errors are intentionally swallowed so
// diagnostics can never break the auth flow.
func (h *Handlers) logSSOEvent(r *http.Request, providerID, outcome, errCode string,
	externalID, email, roleGranted *string) {
	if h.pool == nil || providerID == "" {
		return // pre-state-lookup errors have no provider_id; nothing to log
	}
	redacted, _ := json.Marshal(redactClaims(r))
	ip := clientIP(r)
	ua := r.UserAgent()
	_, _ = h.pool.Exec(r.Context(), `
		INSERT INTO auth.sso_login_events
		    (provider_id, outcome, error_code, external_id, email,
		     role_granted, claims_redacted, ip_address, user_agent)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, NULLIF($8, '')::inet, $9)
	`, providerID, outcome, errCode, externalID, email, roleGranted,
		redacted, ip, ua)
}

// redactClaims returns a minimal diagnostic record of the callback
// request query string (NOT the id_token claims — those live elsewhere).
// Query values are truncated to 64 chars; keys matching secret-looking
// patterns are dropped.
func redactClaims(r *http.Request) map[string]any {
	out := map[string]any{}
	for k, vals := range r.URL.Query() {
		if secretKeyRE.MatchString(k) {
			continue
		}
		if len(vals) == 0 {
			continue
		}
		v := vals[0]
		if len(v) > 64 {
			v = v[:64] + "…"
		}
		out[k] = v
	}
	return out
}

var secretKeyRE = regexp.MustCompile(`(?i)(secret|token|password|key|hash)`)

// clientIP extracts the originating client IP from an http.Request,
// preferring X-Forwarded-For when the platform is deployed behind nginx.
// Returns "" if no IP is usable (the caller writes NULLIF on the insert).
func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.Index(xf, ","); i > 0 {
			return strings.TrimSpace(xf[:i])
		}
		return strings.TrimSpace(xf)
	}
	// r.RemoteAddr is "ip:port" — strip port.
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// deriveUsername produces a URL-safe, display-friendly username from an
// IdP sub or email local-part. Lower-cased, alnum+`-_.`, ≤ 64 chars.
func deriveUsername(sub, email string) string {
	base := sub
	if base == "" || len(base) > 64 {
		if at := strings.Index(email, "@"); at > 0 {
			base = email[:at]
		}
	}
	out := make([]byte, 0, len(base))
	for i := 0; i < len(base); i++ {
		c := base[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "sso-user"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
}

func hashHex6(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:6]
}

func randomURLSafe(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
