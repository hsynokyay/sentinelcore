// Package ssostate provides a 5-minute single-use Redis store for
// SSO start-callback state (state token, PKCE verifier, nonce, return_to).
package ssostate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrStateNotFound is returned by Take when the state key does not exist
// (expired, already consumed, or never written). Callers treat all three
// reasons identically — each is security-equivalent: the request is invalid.
var ErrStateNotFound = errors.New("ssostate: state not found")

// DefaultTTL matches the spec's 5-minute window.
const DefaultTTL = 5 * time.Minute

// State is the payload stashed between /start and /callback.
// JSON-serialised for Redis storage.
type State struct {
	OrgID        string    `json:"org_id"`
	ProviderID   string    `json:"provider_id"`
	PKCEVerifier string    `json:"pkce_verifier"`
	Nonce        string    `json:"nonce"`
	ReturnTo     string    `json:"return_to"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Store is the single-use state store.
type Store struct {
	client *redis.Client
}

func New(client *redis.Client) *Store {
	return &Store{client: client}
}

// Put writes state with the default 5-minute TTL.
func (s *Store) Put(ctx context.Context, stateToken string, v State) error {
	return s.PutWithTTL(ctx, stateToken, v, DefaultTTL)
}

// PutWithTTL writes state with an explicit TTL (test helper).
func (s *Store) PutWithTTL(ctx context.Context, stateToken string, v State, ttl time.Duration) error {
	if stateToken == "" {
		return errors.New("ssostate: empty state token")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ssostate: marshal: %w", err)
	}
	return s.client.Set(ctx, stateKey(stateToken), b, ttl).Err()
}

// Take atomically reads + deletes state. Guarantees single-use: any second
// Take with the same token returns ErrStateNotFound.
//
// Uses Redis GETDEL (>= 6.2) so there is no race between GET and DEL.
func (s *Store) Take(ctx context.Context, stateToken string) (State, error) {
	if stateToken == "" {
		return State{}, ErrStateNotFound
	}
	raw, err := s.client.GetDel(ctx, stateKey(stateToken)).Bytes()
	if errors.Is(err, redis.Nil) {
		return State{}, ErrStateNotFound
	}
	if err != nil {
		return State{}, fmt.Errorf("ssostate: GETDEL: %w", err)
	}
	var v State
	if err := json.Unmarshal(raw, &v); err != nil {
		return State{}, fmt.Errorf("ssostate: unmarshal: %w", err)
	}
	return v, nil
}

func stateKey(t string) string { return "sso:state:" + t }
