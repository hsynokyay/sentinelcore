package authbroker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// BearerStrategy injects a static bearer token into the Authorization header.
type BearerStrategy struct{}

func (s *BearerStrategy) Name() string { return "bearer" }

func (s *BearerStrategy) Authenticate(_ context.Context, cfg AuthConfig) (*Session, error) {
	token, ok := cfg.Credentials["token"]
	if !ok || token == "" {
		return nil, fmt.Errorf("bearer: missing 'token' in credentials")
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour // static tokens don't expire, but sessions do
	}

	return &Session{
		Headers:   map[string]string{"Authorization": "Bearer " + token},
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

func (s *BearerStrategy) Refresh(_ context.Context, session *Session, cfg AuthConfig) (*Session, error) {
	return s.Authenticate(context.Background(), cfg)
}

func (s *BearerStrategy) Validate(_ context.Context, session *Session) (bool, error) {
	return !session.IsExpired() && session.Headers["Authorization"] != "", nil
}

// OAuth2CCStrategy implements OAuth2 Client Credentials flow.
type OAuth2CCStrategy struct {
	HTTPClient *http.Client // override for testing
}

func (s *OAuth2CCStrategy) Name() string { return "oauth2_cc" }

func (s *OAuth2CCStrategy) Authenticate(ctx context.Context, cfg AuthConfig) (*Session, error) {
	clientID, ok := cfg.Credentials["client_id"]
	if !ok {
		return nil, fmt.Errorf("oauth2_cc: missing 'client_id'")
	}
	clientSecret, ok := cfg.Credentials["client_secret"]
	if !ok {
		return nil, fmt.Errorf("oauth2_cc: missing 'client_secret'")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("oauth2_cc: missing token endpoint")
	}

	// SSRF protection: reject token endpoints pointing at internal/private IPs.
	// Skip when HTTPClient is overridden (test mode with controlled client).
	if s.HTTPClient == nil {
		if err := validateEndpointNotInternal(cfg.Endpoint); err != nil {
			return nil, fmt.Errorf("oauth2_cc: %w", err)
		}
	}

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scope, ok := cfg.ExtraParams["scope"]; ok {
		data.Set("scope", scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2_cc: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2_cc: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("oauth2_cc: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("oauth2_cc: failed to decode response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("oauth2_cc: empty access token in response")
	}

	ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
	if ttl == 0 {
		ttl = time.Hour
	}

	tokenType := tokenResp.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	return &Session{
		Headers:   map[string]string{"Authorization": tokenType + " " + tokenResp.AccessToken},
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

func (s *OAuth2CCStrategy) Refresh(ctx context.Context, _ *Session, cfg AuthConfig) (*Session, error) {
	return s.Authenticate(ctx, cfg) // CC flow: just re-authenticate
}

func (s *OAuth2CCStrategy) Validate(_ context.Context, session *Session) (bool, error) {
	return !session.IsExpired() && session.Headers["Authorization"] != "", nil
}

// FormLoginStrategy authenticates via HTML form POST and captures session cookies.
type FormLoginStrategy struct {
	HTTPClient *http.Client
}

func (s *FormLoginStrategy) Name() string { return "form_login" }

func (s *FormLoginStrategy) Authenticate(ctx context.Context, cfg AuthConfig) (*Session, error) {
	username, ok := cfg.Credentials["username"]
	if !ok {
		return nil, fmt.Errorf("form_login: missing 'username'")
	}
	password, ok := cfg.Credentials["password"]
	if !ok {
		return nil, fmt.Errorf("form_login: missing 'password'")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("form_login: missing login endpoint")
	}

	// SSRF protection: skip when HTTPClient is overridden (test mode).
	if s.HTTPClient == nil {
		if err := validateEndpointNotInternal(cfg.Endpoint); err != nil {
			return nil, fmt.Errorf("form_login: %w", err)
		}
	}

	usernameField := cfg.ExtraParams["username_field"]
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := cfg.ExtraParams["password_field"]
	if passwordField == "" {
		passwordField = "password"
	}

	data := url.Values{
		usernameField: {username},
		passwordField: {password},
	}
	for k, v := range cfg.ExtraParams {
		if k != "username_field" && k != "password_field" {
			data.Set(k, v)
		}
	}

	client := s.HTTPClient
	if client == nil {
		jar, _ := cookieJar()
		client = &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("form_login: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("form_login: login request failed: %w", err)
	}
	defer resp.Body.Close()

	// Collect cookies from the response and jar
	parsedURL, _ := url.Parse(cfg.Endpoint)
	cookies := client.Jar.Cookies(parsedURL)
	if len(cookies) == 0 {
		return nil, fmt.Errorf("form_login: no session cookies received")
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = time.Hour
	}

	return &Session{
		Cookies:   cookies,
		Headers:   make(map[string]string),
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

func (s *FormLoginStrategy) Refresh(ctx context.Context, _ *Session, cfg AuthConfig) (*Session, error) {
	return s.Authenticate(ctx, cfg)
}

func (s *FormLoginStrategy) Validate(_ context.Context, session *Session) (bool, error) {
	return !session.IsExpired() && len(session.Cookies) > 0, nil
}

// APIKeyStrategy injects an API key into a header, query param, or cookie.
type APIKeyStrategy struct{}

func (s *APIKeyStrategy) Name() string { return "api_key" }

func (s *APIKeyStrategy) Authenticate(_ context.Context, cfg AuthConfig) (*Session, error) {
	key, ok := cfg.Credentials["api_key"]
	if !ok || key == "" {
		return nil, fmt.Errorf("api_key: missing 'api_key' in credentials")
	}

	location := cfg.ExtraParams["location"] // header, query, cookie
	if location == "" {
		location = "header"
	}
	name := cfg.ExtraParams["name"]
	if name == "" {
		name = "X-API-Key"
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	session := &Session{
		Headers:   make(map[string]string),
		ExpiresAt: time.Now().Add(ttl),
	}

	switch location {
	case "header":
		session.Headers[name] = key
	case "cookie":
		session.Cookies = []*http.Cookie{{Name: name, Value: key}}
	default:
		return nil, fmt.Errorf("api_key: unsupported location %q (use 'header' or 'cookie')", location)
	}

	return session, nil
}

func (s *APIKeyStrategy) Refresh(_ context.Context, _ *Session, cfg AuthConfig) (*Session, error) {
	return s.Authenticate(context.Background(), cfg)
}

func (s *APIKeyStrategy) Validate(_ context.Context, session *Session) (bool, error) {
	return !session.IsExpired(), nil
}

// BasicStrategy injects HTTP Basic authentication into the Authorization header.
// Credentials are expected as username + password.
type BasicStrategy struct{}

func (s *BasicStrategy) Name() string { return "basic" }

func (s *BasicStrategy) Authenticate(_ context.Context, cfg AuthConfig) (*Session, error) {
	user, ok := cfg.Credentials["username"]
	if !ok || user == "" {
		return nil, fmt.Errorf("basic: missing 'username' in credentials")
	}
	pass, ok := cfg.Credentials["password"]
	if !ok {
		return nil, fmt.Errorf("basic: missing 'password' in credentials")
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return &Session{
		Headers:   map[string]string{"Authorization": "Basic " + encoded},
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

func (s *BasicStrategy) Refresh(_ context.Context, _ *Session, cfg AuthConfig) (*Session, error) {
	return s.Authenticate(context.Background(), cfg)
}

func (s *BasicStrategy) Validate(_ context.Context, session *Session) (bool, error) {
	return !session.IsExpired() && session.Headers["Authorization"] != "", nil
}

// validateEndpointNotInternal prevents SSRF via auth endpoints pointing at
// internal infrastructure (cloud metadata, private networks, loopback).
func validateEndpointNotInternal(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("endpoint scheme %q not allowed (use http or https)", scheme)
	}

	hostname := parsed.Hostname()

	// Check if hostname is a raw IP
	if ip := net.ParseIP(hostname); ip != nil {
		if scope.IsBlockedIP(ip) {
			return fmt.Errorf("endpoint resolves to blocked IP %s", ip)
		}
		return nil
	}

	// Resolve hostname and check all IPs
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return fmt.Errorf("cannot resolve endpoint host %q: %w", hostname, err)
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && scope.IsBlockedIP(ip) {
			return fmt.Errorf("endpoint host %q resolves to blocked IP %s", hostname, ip)
		}
	}

	return nil
}

// SessionImportStrategy authenticates by loading a pre-captured session bundle
// from the BundleStore. It does not perform any live authentication flow —
// credentials were captured out-of-band and stored encrypted in the DB.
//
// NOTE: This strategy is NOT registered in NewBroker. Wiring requires a live
// BundleStore at startup; PR D will wire it in the controlplane. Instantiate
// via &SessionImportStrategy{Bundles: store} and call RegisterStrategy.
type SessionImportStrategy struct {
	Bundles bundles.BundleStore
}

// Name returns the strategy identifier "session_import".
func (s *SessionImportStrategy) Name() string { return "session_import" }

// Authenticate loads the bundle identified by cfg.BundleID/CustomerID, checks
// the ACL for cfg.ProjectID/ScopeID, and returns a Session from the stored
// cookies and headers.
func (s *SessionImportStrategy) Authenticate(ctx context.Context, cfg AuthConfig) (*Session, error) {
	if cfg.BundleID == "" {
		return nil, fmt.Errorf("session_import: bundle_id required")
	}
	if cfg.CustomerID == "" {
		return nil, fmt.Errorf("session_import: customer_id required")
	}
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("session_import: project_id required")
	}
	if s.Bundles == nil {
		return nil, fmt.Errorf("session_import: bundle store not configured")
	}

	b, err := s.Bundles.Load(ctx, cfg.BundleID, cfg.CustomerID)
	if err != nil {
		return nil, fmt.Errorf("session_import: load: %w", err)
	}
	if b.Type != "session_import" {
		return nil, fmt.Errorf("session_import: wrong bundle type %q", b.Type)
	}
	if b.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session_import: expired")
	}

	var scopeID *string
	if cfg.ScopeID != "" {
		v := cfg.ScopeID
		scopeID = &v
	}
	ok, err := s.Bundles.CheckACL(ctx, b.ID, cfg.ProjectID, scopeID)
	if err != nil {
		return nil, fmt.Errorf("session_import: acl: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("session_import: bundle not authorized for project")
	}

	httpCookies := make([]*http.Cookie, 0, len(b.CapturedSession.Cookies))
	for _, c := range b.CapturedSession.Cookies {
		httpCookies = append(httpCookies, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			HttpOnly: c.HttpOnly,
			Secure:   c.Secure,
		})
	}
	headers := make(map[string]string, len(b.CapturedSession.Headers))
	for k, v := range b.CapturedSession.Headers {
		headers[k] = v
	}

	_ = s.Bundles.IncUseCount(ctx, b.ID)

	return &Session{
		Cookies:   httpCookies,
		Headers:   headers,
		ExpiresAt: b.ExpiresAt,
	}, nil
}

// Refresh is not supported for session_import bundles; the operator must
// re-upload a fresh session capture.
func (s *SessionImportStrategy) Refresh(_ context.Context, _ *Session, _ AuthConfig) (*Session, error) {
	return nil, fmt.Errorf("session_import: manual re-upload required")
}

// Validate returns true if the session is not expired and has at least one
// cookie or header.
func (s *SessionImportStrategy) Validate(_ context.Context, session *Session) (bool, error) {
	return !session.IsExpired() && (len(session.Cookies) > 0 || len(session.Headers) > 0), nil
}
