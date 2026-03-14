package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTestLimiter(t *testing.T) (*Limiter, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	return NewLimiter(client), mr
}

func TestLimiter_Allow(t *testing.T) {
	limiter, _ := setupTestLimiter(t)
	ctx := context.Background()

	// First request should be allowed
	result, err := limiter.Allow(ctx, "user:1", 3, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !result.Allowed {
		t.Error("first request should be allowed")
	}
	if result.Remaining != 2 {
		t.Errorf("remaining = %d, want 2", result.Remaining)
	}
}

func TestLimiter_ExceedLimit(t *testing.T) {
	limiter, _ := setupTestLimiter(t)
	ctx := context.Background()

	limit := 3
	for i := 0; i < limit; i++ {
		result, err := limiter.Allow(ctx, "user:2", limit, time.Minute)
		if err != nil {
			t.Fatalf("Allow #%d: %v", i+1, err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// This should be denied
	result, err := limiter.Allow(ctx, "user:2", limit, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if result.Allowed {
		t.Error("request exceeding limit should be denied")
	}
	if result.Remaining != 0 {
		t.Errorf("remaining = %d, want 0", result.Remaining)
	}
}

func TestLimiter_DifferentKeys(t *testing.T) {
	limiter, _ := setupTestLimiter(t)
	ctx := context.Background()

	r1, _ := limiter.Allow(ctx, "user:a", 1, time.Minute)
	r2, _ := limiter.Allow(ctx, "user:b", 1, time.Minute)

	if !r1.Allowed || !r2.Allowed {
		t.Error("different keys should have independent limits")
	}
}

func TestLimiter_WindowExpiry(t *testing.T) {
	limiter, mr := setupTestLimiter(t)
	ctx := context.Background()

	// Exhaust the limit
	limiter.Allow(ctx, "user:3", 1, time.Minute)
	result, _ := limiter.Allow(ctx, "user:3", 1, time.Minute)
	if result.Allowed {
		t.Error("should be denied after exhausting limit")
	}

	// Fast-forward time in miniredis
	mr.FastForward(2 * time.Minute)

	// Should be allowed again
	result, _ = limiter.Allow(ctx, "user:3", 1, time.Minute)
	if !result.Allowed {
		t.Error("should be allowed after window expires")
	}
}
