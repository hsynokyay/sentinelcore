package authbroker

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/replay"
	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
)

// RecordedLoginStrategy authenticates by loading a bundle of type
// 'recorded_login'. In v1 (one-shot mode), it returns the captured session
// directly. Plan #4 adds automatable refresh that replays the recorded
// action list to obtain a fresh session. Plan #5 (PR C) adds a
// credentials.Store so the replayer can resolve ActionFill secrets at
// refresh time.
type RecordedLoginStrategy struct {
	Bundles  bundles.BundleStore
	Replayer *replay.Engine    // optional; nil disables automatable refresh
	Creds    credentials.Store // optional; required for bundles with ActionFill steps
}

func (s *RecordedLoginStrategy) Name() string { return "recorded_login" }

func (s *RecordedLoginStrategy) Authenticate(ctx context.Context, cfg AuthConfig) (*Session, error) {
	if cfg.BundleID == "" {
		return nil, fmt.Errorf("recorded_login: bundle_id required")
	}
	if cfg.CustomerID == "" {
		return nil, fmt.Errorf("recorded_login: customer_id required")
	}
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("recorded_login: project_id required")
	}
	if s.Bundles == nil {
		return nil, fmt.Errorf("recorded_login: bundle store not configured")
	}

	b, err := s.Bundles.Load(ctx, cfg.BundleID, cfg.CustomerID)
	if err != nil {
		return nil, fmt.Errorf("recorded_login: load: %w", err)
	}
	if b.Type != "recorded_login" {
		return nil, fmt.Errorf("recorded_login: wrong bundle type %q", b.Type)
	}
	if b.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("recorded_login: bundle expired")
	}

	var scopeID *string
	if cfg.ScopeID != "" {
		v := cfg.ScopeID
		scopeID = &v
	}
	ok, err := s.Bundles.CheckACL(ctx, b.ID, cfg.ProjectID, scopeID)
	if err != nil {
		return nil, fmt.Errorf("recorded_login: acl: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("recorded_login: bundle not authorized for project")
	}

	httpCookies := make([]*http.Cookie, 0, len(b.CapturedSession.Cookies))
	for _, c := range b.CapturedSession.Cookies {
		httpCookies = append(httpCookies, &http.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			HttpOnly: c.HttpOnly, Secure: c.Secure,
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

func (s *RecordedLoginStrategy) Refresh(ctx context.Context, _ *Session, cfg AuthConfig) (*Session, error) {
	if cfg.BundleID == "" {
		return nil, fmt.Errorf("recorded_login: bundle_id required")
	}
	if cfg.CustomerID == "" {
		return nil, fmt.Errorf("recorded_login: customer_id required")
	}
	if s.Bundles == nil {
		return nil, fmt.Errorf("recorded_login: bundle store not configured")
	}

	b, err := s.Bundles.Load(ctx, cfg.BundleID, cfg.CustomerID)
	if err != nil {
		return nil, fmt.Errorf("recorded_login: load: %w", err)
	}
	if !b.AutomatableRefresh {
		return nil, fmt.Errorf("recorded_login: bundle is one-shot only (re-record required)")
	}
	if s.Replayer == nil {
		return nil, fmt.Errorf("recorded_login: replay engine not configured")
	}

	// Wire the credential store onto the engine so ActionFill steps can
	// resolve secrets. Nil is permitted and simply means the replayer will
	// refuse any bundle that has fill actions.
	eng := s.Replayer.WithCredentials(s.Creds)
	res, err := eng.Replay(ctx, b)
	if err != nil {
		return nil, fmt.Errorf("recorded_login: replay: %w", err)
	}

	return &Session{
		Cookies:   res.Cookies,
		Headers:   res.Headers,
		ExpiresAt: time.Now().Add(time.Duration(b.TTLSeconds) * time.Second),
	}, nil
}

func (s *RecordedLoginStrategy) Validate(_ context.Context, session *Session) (bool, error) {
	return !session.IsExpired() && (len(session.Cookies) > 0 || len(session.Headers) > 0), nil
}
