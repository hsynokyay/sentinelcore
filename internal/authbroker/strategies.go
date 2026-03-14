package authbroker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
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
