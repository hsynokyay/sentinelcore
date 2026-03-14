package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter implements a Redis-backed fixed-window rate limiter.
type Limiter struct {
	client *redis.Client
}

// NewLimiter creates a new rate limiter backed by the given Redis client.
func NewLimiter(client *redis.Client) *Limiter {
	return &Limiter{client: client}
}

// Result holds the outcome of a rate limit check.
type Result struct {
	Allowed   bool
	Remaining int
	ResetAt   time.Time
}

// Allow checks if the request is within the rate limit.
// Uses a simple fixed-window counter with INCR + EXPIRE.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	redisKey := fmt.Sprintf("ratelimit:%s", key)

	count, err := l.client.Incr(ctx, redisKey).Result()
	if err != nil {
		return nil, fmt.Errorf("ratelimit: incr: %w", err)
	}

	if count == 1 {
		l.client.Expire(ctx, redisKey, window)
	}

	ttl, _ := l.client.TTL(ctx, redisKey).Result()

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	return &Result{
		Allowed:   count <= int64(limit),
		Remaining: remaining,
		ResetAt:   time.Now().Add(ttl),
	}, nil
}
