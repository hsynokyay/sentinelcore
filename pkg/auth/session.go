package auth

import (
	"context"
	"errors"
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

// sessionIndexTTL is how long a user's JTI index set lives in Redis
// after last use. It must be at least as long as the refresh-token TTL
// so that RevokeAllForUser never misses a JTI still in circulation.
const sessionIndexTTL = 7 * 24 * time.Hour

// CreateSession stores a session:<jti> → userID string with the given TTL.
// Phase 2: also adds jti to a user-indexed set user:<userID>:sessions
// so RevokeAllForUser can locate every active JTI for the user.
func (s *SessionStore) CreateSession(ctx context.Context, jti string, userID string, ttl time.Duration) error {
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, "session:"+jti, userID, ttl)
	indexKey := "user:" + userID + ":sessions"
	pipe.SAdd(ctx, indexKey, jti)
	pipe.Expire(ctx, indexKey, sessionIndexTTL)
	_, err := pipe.Exec(ctx)
	return err
}

// RevokeSession removes a single session. Also SREM's the jti from the
// user-indexed set so a later RevokeAllForUser sweep doesn't try to
// re-delete a non-existent session.
func (s *SessionStore) RevokeSession(ctx context.Context, jti string) error {
	// Look up userID first so we can SREM the index.
	userID, err := s.client.Get(ctx, "session:"+jti).Result()
	if errors.Is(err, redis.Nil) {
		// Already gone; nothing to index-remove.
		return nil
	}
	if err != nil {
		return err
	}
	pipe := s.client.TxPipeline()
	pipe.Del(ctx, "session:"+jti)
	pipe.SRem(ctx, "user:"+userID+":sessions", jti)
	_, err = pipe.Exec(ctx)
	return err
}

// IsActive checks whether a session exists in Redis.
func (s *SessionStore) IsActive(ctx context.Context, jti string) (bool, error) {
	exists, err := s.client.Exists(ctx, "session:"+jti).Result()
	return exists > 0, err
}

// RevokeAllForUser drains every JTI currently associated with the user.
// Uses SPOP in a loop (atomic remove-one-from-set per call) to avoid
// losing concurrent session creations. New sessions created after this
// call starts are NOT revoked — they land in the set post-drain and
// are legitimately post-revocation.
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
	key := "user:" + userID + ":sessions"
	for {
		jti, err := s.client.SPop(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.client.Del(ctx, "session:"+jti).Err(); err != nil {
			// Log-only: SPOP already removed it from the index; the
			// session key is orphaned for its TTL at worst.
			// Caller gets the error so they can decide to retry.
			return err
		}
	}
}

// Close closes the underlying Redis client.
func (s *SessionStore) Close() error {
	return s.client.Close()
}
