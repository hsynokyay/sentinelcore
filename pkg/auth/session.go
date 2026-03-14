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
func (s *SessionStore) CreateSession(ctx context.Context, jti string, userID string, ttl time.Duration) error {
	return s.client.Set(ctx, "session:"+jti, userID, ttl).Err()
}

// RevokeSession removes a session from Redis.
func (s *SessionStore) RevokeSession(ctx context.Context, jti string) error {
	return s.client.Del(ctx, "session:"+jti).Err()
}

// IsActive checks whether a session exists in Redis.
func (s *SessionStore) IsActive(ctx context.Context, jti string) (bool, error) {
	exists, err := s.client.Exists(ctx, "session:"+jti).Result()
	return exists > 0, err
}

// Close closes the underlying Redis client.
func (s *SessionStore) Close() error {
	return s.client.Close()
}
