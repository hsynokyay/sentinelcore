package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SessionStore manages JWT sessions in Redis for revocation tracking.
type SessionStore struct {
	client *redis.Client
}

// NewSessionStore creates a new SessionStore connected to the given Redis URL.
func NewSessionStore(redisURL string) (*SessionStore, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("auth: parse redis URL: %w", err)
	}
	client := redis.NewClient(opts)
	return &SessionStore{client: client}, nil
}

// NewSessionStoreFromClient creates a SessionStore from an existing Redis client.
func NewSessionStoreFromClient(client *redis.Client) *SessionStore {
	return &SessionStore{client: client}
}

// CreateSession stores a session in Redis with the given TTL.
// Also initializes the last-activity timestamp for idle timeout tracking.
func (s *SessionStore) CreateSession(ctx context.Context, jti string, userID string, ttl time.Duration) error {
	pipe := s.client.Pipeline()
	pipe.Set(ctx, "session:"+jti, userID, ttl)
	pipe.Set(ctx, "session:"+jti+":activity", time.Now().Unix(), ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// RevokeSession removes a session and its activity tracking from Redis.
func (s *SessionStore) RevokeSession(ctx context.Context, jti string) error {
	return s.client.Del(ctx, "session:"+jti, "session:"+jti+":activity").Err()
}

// IsActive checks whether a session exists in Redis.
func (s *SessionStore) IsActive(ctx context.Context, jti string) (bool, error) {
	exists, err := s.client.Exists(ctx, "session:"+jti).Result()
	return exists > 0, err
}

// TouchSession updates the last-activity timestamp for idle timeout tracking.
// Called on every authenticated request.
func (s *SessionStore) TouchSession(ctx context.Context, jti string, ttl time.Duration) error {
	return s.client.Set(ctx, "session:"+jti+":activity", time.Now().Unix(), ttl).Err()
}

// IsIdle checks if a session has been idle longer than the given timeout.
// Returns true if idle (should be rejected), false if active.
func (s *SessionStore) IsIdle(ctx context.Context, jti string, idleTimeout time.Duration) (bool, error) {
	val, err := s.client.Get(ctx, "session:"+jti+":activity").Int64()
	if err != nil {
		// No activity record — treat as not idle (backward compat with existing sessions)
		return false, nil
	}
	lastActivity := time.Unix(val, 0)
	return time.Since(lastActivity) > idleTimeout, nil
}

// Close closes the underlying Redis client.
func (s *SessionStore) Close() error {
	return s.client.Close()
}
