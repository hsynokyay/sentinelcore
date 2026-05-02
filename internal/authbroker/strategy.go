// Package authbroker implements the Auth Session Broker for managing
// authenticated DAST scanning sessions across multiple auth strategies.
package authbroker

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Session represents an authenticated scanning session.
type Session struct {
	ID        string
	ScanJobID string
	Strategy  string
	Headers   map[string]string
	Cookies   []*http.Cookie
	ExpiresAt time.Time
	CreatedAt time.Time
	Status    string // active, expired, revoked
}

// IsExpired returns true if the session has passed its expiry time.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// NeedsRefresh returns true if the session expires within the given buffer.
func (s *Session) NeedsRefresh(buffer time.Duration) bool {
	return time.Now().Add(buffer).After(s.ExpiresAt)
}

// ApplyTo injects session credentials into an HTTP request.
func (s *Session) ApplyTo(req *http.Request) {
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	for _, c := range s.Cookies {
		req.AddCookie(c)
	}
}

// AuthConfig holds the configuration for an auth strategy.
type AuthConfig struct {
	Strategy    string            `json:"strategy"`
	Credentials map[string]string `json:"credentials"` // fetched from Vault, never persisted
	Endpoint    string            `json:"endpoint"`     // auth endpoint URL
	ExtraParams map[string]string `json:"extra_params"`
	TTL         time.Duration     `json:"ttl"`
}

// Strategy defines how to authenticate with a target.
type Strategy interface {
	Name() string
	Authenticate(ctx context.Context, cfg AuthConfig) (*Session, error)
	Refresh(ctx context.Context, session *Session, cfg AuthConfig) (*Session, error)
	Validate(ctx context.Context, session *Session) (bool, error)
}

// Broker manages auth sessions for DAST scans.
type Broker struct {
	mu         sync.RWMutex
	sessions   map[string]*Session // sessionID → session
	strategies map[string]Strategy
	logger     zerolog.Logger
}

// NewBroker creates an auth session broker with registered strategies.
func NewBroker(logger zerolog.Logger) *Broker {
	b := &Broker{
		sessions:   make(map[string]*Session),
		strategies: make(map[string]Strategy),
		logger:     logger.With().Str("component", "auth-broker").Logger(),
	}

	// Register built-in strategies
	b.RegisterStrategy(&BearerStrategy{})
	b.RegisterStrategy(&OAuth2CCStrategy{})
	b.RegisterStrategy(&FormLoginStrategy{})
	b.RegisterStrategy(&APIKeyStrategy{})
	b.RegisterStrategy(&BasicStrategy{})

	return b
}

// RegisterStrategy adds an auth strategy.
func (b *Broker) RegisterStrategy(s Strategy) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.strategies[s.Name()] = s
	b.logger.Info().Str("strategy", s.Name()).Msg("registered auth strategy")
}

// CreateSession authenticates and creates a new session.
func (b *Broker) CreateSession(ctx context.Context, scanJobID string, cfg AuthConfig) (*Session, error) {
	b.mu.RLock()
	strategy, ok := b.strategies[cfg.Strategy]
	b.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("authbroker: unknown strategy %q", cfg.Strategy)
	}

	session, err := strategy.Authenticate(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("authbroker: authentication failed for strategy %q: %w", cfg.Strategy, err)
	}

	session.ID = uuid.New().String()
	session.ScanJobID = scanJobID
	session.Strategy = cfg.Strategy
	session.CreatedAt = time.Now()
	session.Status = "active"

	b.mu.Lock()
	b.sessions[session.ID] = session
	b.mu.Unlock()

	b.logger.Info().
		Str("session_id", session.ID).
		Str("scan_job_id", scanJobID).
		Str("strategy", cfg.Strategy).
		Time("expires_at", session.ExpiresAt).
		Msg("session created")

	return session, nil
}

// GetSession retrieves a session by ID.
func (b *Broker) GetSession(sessionID string) (*Session, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	session, ok := b.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("authbroker: session %q not found", sessionID)
	}
	return session, nil
}

// RefreshSession proactively refreshes a session before expiry.
func (b *Broker) RefreshSession(ctx context.Context, sessionID string, cfg AuthConfig) (*Session, error) {
	b.mu.RLock()
	session, ok := b.sessions[sessionID]
	if !ok {
		b.mu.RUnlock()
		return nil, fmt.Errorf("authbroker: session %q not found", sessionID)
	}
	strategy, stratOk := b.strategies[session.Strategy]
	b.mu.RUnlock()

	if !stratOk {
		return nil, fmt.Errorf("authbroker: strategy %q not found", session.Strategy)
	}

	refreshed, err := strategy.Refresh(ctx, session, cfg)
	if err != nil {
		return nil, fmt.Errorf("authbroker: refresh failed: %w", err)
	}

	refreshed.ID = session.ID
	refreshed.ScanJobID = session.ScanJobID
	refreshed.Strategy = session.Strategy
	refreshed.CreatedAt = session.CreatedAt
	refreshed.Status = "active"

	b.mu.Lock()
	b.sessions[sessionID] = refreshed
	b.mu.Unlock()

	b.logger.Info().
		Str("session_id", sessionID).
		Time("new_expires_at", refreshed.ExpiresAt).
		Msg("session refreshed")

	return refreshed, nil
}

// RevokeSession marks a session as revoked and removes credentials.
func (b *Broker) RevokeSession(sessionID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	session, ok := b.sessions[sessionID]
	if !ok {
		return fmt.Errorf("authbroker: session %q not found", sessionID)
	}

	session.Status = "revoked"
	session.Headers = nil
	session.Cookies = nil
	delete(b.sessions, sessionID)

	b.logger.Info().Str("session_id", sessionID).Msg("session revoked")
	return nil
}

// RevokeScanSessions revokes all sessions for a scan job.
func (b *Broker) RevokeScanSessions(scanJobID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	count := 0
	for id, session := range b.sessions {
		if session.ScanJobID == scanJobID {
			session.Status = "revoked"
			session.Headers = nil
			session.Cookies = nil
			delete(b.sessions, id)
			count++
		}
	}

	b.logger.Info().
		Str("scan_job_id", scanJobID).
		Int("revoked_count", count).
		Msg("scan sessions revoked")
	return count
}

// CleanExpired removes all expired sessions.
func (b *Broker) CleanExpired() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	count := 0
	for id, session := range b.sessions {
		if session.IsExpired() {
			session.Headers = nil
			session.Cookies = nil
			delete(b.sessions, id)
			count++
		}
	}
	return count
}
