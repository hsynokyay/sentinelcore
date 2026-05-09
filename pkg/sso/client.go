package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrNonceMismatch   = errors.New("sso: id_token nonce does not match stored nonce")
	ErrIssuerMismatch  = errors.New("sso: id_token issuer does not match provider")
	ErrAudMismatch     = errors.New("sso: id_token audience does not match client_id")
	ErrTokenExpired    = errors.New("sso: id_token expired")
	ErrClaimsMalformed = errors.New("sso: id_token claims could not be parsed")
)

// Config is the minimum set needed to construct an OIDC client for one
// provider. Corresponds to a single row in auth.oidc_providers.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Claims holds the subset of id_token claims we use. Raw retains the full
// claim payload for diagnostics / auditing (with secrets redacted upstream).
type Claims struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	Raw    map[string]any
}

// Client wraps a cached go-oidc Provider + oauth2.Config. Construction
// performs discovery (1 HTTP call) + JWKS fetch (1 more); callers should
// cache instances per-provider rather than constructing fresh per-request.
type Client struct {
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	oauth2Cfg oauth2.Config
	issuerURL string
	clientID  string
}

// New performs OIDC discovery against cfg.IssuerURL and returns a ready
// Client. For local dev (http://localhost / 127.0.0.1) discovery is
// permitted in cleartext.
func New(ctx context.Context, cfg Config) (*Client, error) {
	ctx = maybeInsecure(ctx, cfg.IssuerURL)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("sso: discovery: %w", err)
	}
	return &Client{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: []string{"RS256", "ES256"},
			Now:                  time.Now,
		}),
		oauth2Cfg: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		issuerURL: cfg.IssuerURL,
		clientID:  cfg.ClientID,
	}, nil
}

// AuthorizeURL returns the full URL to 302 the browser to. state, nonce,
// and pkceChallenge must be generated fresh per login attempt.
func (c *Client) AuthorizeURL(state, nonce, pkceChallenge string) string {
	return c.oauth2Cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange trades an authorization code for an id_token.
func (c *Client) Exchange(ctx context.Context, code, pkceVerifier string) (string, error) {
	ctx = maybeInsecure(ctx, c.issuerURL)
	tok, err := c.oauth2Cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", pkceVerifier))
	if err != nil {
		return "", fmt.Errorf("sso: token exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", errors.New("sso: token response missing id_token")
	}
	return raw, nil
}

// VerifyIDToken validates signature, iss, aud, exp, and nonce on the
// supplied id_token. Sentinel errors (ErrNonceMismatch, ErrAudMismatch,
// ErrIssuerMismatch, ErrTokenExpired, ErrClaimsMalformed) are wrapped
// with %w so callers can errors.Is-check them for sso_login_events.error_code.
//
// We pre-parse iss/aud/exp/nonce BEFORE calling go-oidc's Verify so our
// sentinel classification is authoritative rather than depending on
// go-oidc's opaque error strings. Signature verification still goes
// through go-oidc (cached JWKS, kid rotation).
func (c *Client) VerifyIDToken(ctx context.Context, rawIDToken, expectedNonce string) (*Claims, error) {
	ctx = maybeInsecure(ctx, c.issuerURL)

	claimsRaw, err := parseJWTClaimsUnverified(rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaimsMalformed, err)
	}
	if iss, _ := claimsRaw["iss"].(string); iss != c.issuerURL {
		return nil, fmt.Errorf("%w: got %q want %q", ErrIssuerMismatch, iss, c.issuerURL)
	}
	if !audContains(claimsRaw["aud"], c.clientID) {
		return nil, fmt.Errorf("%w: aud does not contain %q", ErrAudMismatch, c.clientID)
	}
	if exp, ok := claimsRaw["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, ErrTokenExpired
		}
	}
	if gotNonce, _ := claimsRaw["nonce"].(string); gotNonce != expectedNonce {
		return nil, ErrNonceMismatch
	}

	tok, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("sso: id_token verify: %w", err)
	}

	var out Claims
	if err := tok.Claims(&out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaimsMalformed, err)
	}
	out.Raw = claimsRaw
	return &out, nil
}

// EndSessionURL returns the provider's end_session_endpoint if discovery
// advertised one. Empty string if not supported.
func (c *Client) EndSessionURL() string {
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = c.provider.Claims(&claims)
	return claims.EndSessionEndpoint
}

// parseJWTClaimsUnverified decodes the claims segment without signature
// verification. Used only to produce typed errors before handing off to
// go-oidc. Never trust these values until Verify() succeeds.
func parseJWTClaimsUnverified(raw string) (map[string]any, error) {
	segs := strings.Split(raw, ".")
	if len(segs) != 3 {
		return nil, errors.New("malformed jwt: want 3 segments")
	}
	b, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return nil, fmt.Errorf("claims b64: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("claims json: %w", err)
	}
	return m, nil
}

// audContains handles aud being either a string or []string (RFC 7519 §4.1.3).
func audContains(raw any, want string) bool {
	switch v := raw.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func maybeInsecure(ctx context.Context, issuer string) context.Context {
	if strings.HasPrefix(issuer, "http://localhost") ||
		strings.HasPrefix(issuer, "http://127.0.0.1") {
		return oidc.InsecureIssuerURLContext(ctx, issuer)
	}
	return ctx
}
