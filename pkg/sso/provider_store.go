package sso

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/crypto/aesgcm"
)

// Provider is one row of auth.oidc_providers decoded for app use.
// ClientSecret is populated only by Get / GetByOrgSlug; callers must
// never log or echo it to responses.
type Provider struct {
	ID               string
	OrgID            string
	ProviderSlug     string
	DisplayName      string
	IssuerURL        string
	ClientID         string
	ClientSecret     string // plaintext — only from Get/GetByOrgSlug, never from List
	Scopes           []string
	DefaultRoleID    string
	SyncRoleOnLogin  bool
	SSOLogoutEnabled bool
	EndSessionURL    string
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ErrProviderNotFound signals a 404 to handlers.
var ErrProviderNotFound = errors.New("sso: provider not found")

// ProviderStore reads/writes auth.oidc_providers.
//
// Tenancy is enforced at the database layer via RLS — the caller MUST
// have set app.current_org_id (in the session or the transaction) before
// invoking List / Update / Delete. Get and GetByOrgSlug open a transaction
// and set it explicitly.
type ProviderStore struct {
	pool   *pgxpool.Pool
	crypto *aesgcm.Encryptor
}

func NewProviderStore(pool *pgxpool.Pool, crypto *aesgcm.Encryptor) *ProviderStore {
	return &ProviderStore{pool: pool, crypto: crypto}
}

// List returns providers WITHOUT decrypting client_secret. For the
// settings UI which must never reveal secrets.
func (s *ProviderStore) List(ctx context.Context) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, org_id::text, provider_slug, display_name, issuer_url,
		       client_id, scopes, default_role_id, sync_role_on_login,
		       sso_logout_enabled, COALESCE(end_session_url, ''), enabled,
		       created_at, updated_at
		FROM auth.oidc_providers
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list providers: %w", err)
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.OrgID, &p.ProviderSlug, &p.DisplayName,
			&p.IssuerURL, &p.ClientID, &p.Scopes, &p.DefaultRoleID,
			&p.SyncRoleOnLogin, &p.SSOLogoutEnabled, &p.EndSessionURL,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Get returns a provider with its client_secret decrypted. Used by the
// callback handler and the admin edit endpoint (which redacts the value
// before sending it back).
func (s *ProviderStore) Get(ctx context.Context, id string) (Provider, error) {
	var p Provider
	var ciphertext string
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, org_id::text, provider_slug, display_name, issuer_url,
		       client_id, client_secret, scopes, default_role_id, sync_role_on_login,
		       sso_logout_enabled, COALESCE(end_session_url, ''), enabled,
		       created_at, updated_at
		FROM auth.oidc_providers WHERE id = $1
	`, id).Scan(&p.ID, &p.OrgID, &p.ProviderSlug, &p.DisplayName,
		&p.IssuerURL, &p.ClientID, &ciphertext, &p.Scopes, &p.DefaultRoleID,
		&p.SyncRoleOnLogin, &p.SSOLogoutEnabled, &p.EndSessionURL,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, fmt.Errorf("get provider: %w", err)
	}
	secret, err := s.crypto.Decrypt(ciphertext)
	if err != nil {
		return Provider{}, fmt.Errorf("decrypt client_secret: %w", err)
	}
	p.ClientSecret = secret
	return p, nil
}

// GetByOrgSlug looks up a provider by (org_slug, provider_slug). Used by
// the public /start + /callback endpoints. Opens its own transaction and
// sets app.current_org_id once the org.id is resolved, so RLS on the
// provider query is satisfied without requiring a bypass-RLS DB role.
func (s *ProviderStore) GetByOrgSlug(ctx context.Context, orgSlug, providerSlug string) (Provider, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Provider{}, err
	}
	defer tx.Rollback(ctx)

	var orgID string
	err = tx.QueryRow(ctx,
		// `name` doubles as a URL slug — it's kebab-case, unique, and
		// the schema has no separate slug column.
		`SELECT id::text FROM core.organizations WHERE name = $1`, orgSlug).
		Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, err
	}
	// SET does not accept parameter placeholders in PostgreSQL; use
	// set_config(name, value, is_local=true) which has the same semantics
	// as SET LOCAL but can take parametrised args.
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_org_id', $1, true)`, orgID); err != nil {
		return Provider{}, err
	}

	var p Provider
	var ciphertext string
	err = tx.QueryRow(ctx, `
		SELECT id::text, org_id::text, provider_slug, display_name, issuer_url,
		       client_id, client_secret, scopes, default_role_id, sync_role_on_login,
		       sso_logout_enabled, COALESCE(end_session_url, ''), enabled,
		       created_at, updated_at
		FROM auth.oidc_providers
		WHERE org_id = $1 AND provider_slug = $2 AND enabled = true
	`, orgID, providerSlug).Scan(&p.ID, &p.OrgID, &p.ProviderSlug, &p.DisplayName,
		&p.IssuerURL, &p.ClientID, &ciphertext, &p.Scopes, &p.DefaultRoleID,
		&p.SyncRoleOnLogin, &p.SSOLogoutEnabled, &p.EndSessionURL,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Provider{}, err
	}

	secret, err := s.crypto.Decrypt(ciphertext)
	if err != nil {
		return Provider{}, fmt.Errorf("decrypt client_secret: %w", err)
	}
	p.ClientSecret = secret
	return p, nil
}

// Create inserts a new provider with the client_secret encrypted.
func (s *ProviderStore) Create(ctx context.Context, p Provider) (string, error) {
	ct, err := s.crypto.Encrypt(p.ClientSecret)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO auth.oidc_providers (
		    org_id, provider_slug, display_name, issuer_url, client_id,
		    client_secret, scopes, default_role_id, sync_role_on_login,
		    sso_logout_enabled, enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id::text
	`, p.OrgID, p.ProviderSlug, p.DisplayName, p.IssuerURL, p.ClientID,
		ct, p.Scopes, p.DefaultRoleID, p.SyncRoleOnLogin,
		p.SSOLogoutEnabled, p.Enabled).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert provider: %w", err)
	}
	return id, nil
}

// Update modifies a provider. If newSecret is empty, the existing secret
// is preserved (edit-without-re-entering-secret flow).
func (s *ProviderStore) Update(ctx context.Context, id string, p Provider, newSecret string) error {
	if newSecret == "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE auth.oidc_providers SET
			    display_name = $1, issuer_url = $2, client_id = $3,
			    scopes = $4, default_role_id = $5,
			    sync_role_on_login = $6, sso_logout_enabled = $7, enabled = $8
			WHERE id = $9
		`, p.DisplayName, p.IssuerURL, p.ClientID,
			p.Scopes, p.DefaultRoleID, p.SyncRoleOnLogin,
			p.SSOLogoutEnabled, p.Enabled, id)
		return err
	}
	ct, err := s.crypto.Encrypt(newSecret)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE auth.oidc_providers SET
		    display_name = $1, issuer_url = $2, client_id = $3, client_secret = $4,
		    scopes = $5, default_role_id = $6,
		    sync_role_on_login = $7, sso_logout_enabled = $8, enabled = $9
		WHERE id = $10
	`, p.DisplayName, p.IssuerURL, p.ClientID, ct,
		p.Scopes, p.DefaultRoleID, p.SyncRoleOnLogin,
		p.SSOLogoutEnabled, p.Enabled, id)
	return err
}

// Delete removes a provider (cascades to group mappings + login events).
func (s *ProviderStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM auth.oidc_providers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	return nil
}

// UpdateEndSessionURL caches the IdP's end_session_endpoint after first
// successful discovery so SSO logout works without re-running discovery
// on every logout.
func (s *ProviderStore) UpdateEndSessionURL(ctx context.Context, id, endSessionURL string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE auth.oidc_providers SET end_session_url = $1 WHERE id = $2`,
		endSessionURL, id)
	return err
}

// PublicProvider is the redacted view returned by the unauthenticated
// /auth/sso/enabled endpoint — only what the login page needs to render
// buttons. No issuer URL, no client ID, no secret.
type PublicProvider struct {
	ProviderSlug string
	DisplayName  string
}

// ListEnabledPublicByOrgSlug returns enabled providers for an org keyed by
// its URL slug. Pre-auth endpoint — query is constrained by org.slug which
// is a public identifier, so RLS is not required for correctness.
func (s *ProviderStore) ListEnabledPublicByOrgSlug(ctx context.Context, orgSlug string) ([]PublicProvider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT op.provider_slug, op.display_name
		FROM auth.oidc_providers op
		JOIN core.organizations o ON o.id = op.org_id
		WHERE o.name = $1 AND op.enabled = true
		ORDER BY op.display_name ASC
	`, orgSlug)
	if err != nil {
		return nil, fmt.Errorf("list enabled public: %w", err)
	}
	defer rows.Close()
	var out []PublicProvider
	for rows.Next() {
		var p PublicProvider
		if err := rows.Scan(&p.ProviderSlug, &p.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListEnabledForOrg returns enabled providers for an org by UUID. Used by
// the authenticated USE_SSO path to suggest which IdP an SSO-only user
// should use. Caller MUST have set app.current_org_id (RLS applies).
// ClientSecret is intentionally not populated.
func (s *ProviderStore) ListEnabledForOrg(ctx context.Context, orgID string) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, org_id::text, provider_slug, display_name, issuer_url,
		       client_id, scopes, default_role_id, sync_role_on_login,
		       sso_logout_enabled, COALESCE(end_session_url, ''), enabled,
		       created_at, updated_at
		FROM auth.oidc_providers
		WHERE org_id = $1 AND enabled = true
		ORDER BY display_name ASC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list enabled for org: %w", err)
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.OrgID, &p.ProviderSlug, &p.DisplayName,
			&p.IssuerURL, &p.ClientID, &p.Scopes, &p.DefaultRoleID,
			&p.SyncRoleOnLogin, &p.SSOLogoutEnabled, &p.EndSessionURL,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
