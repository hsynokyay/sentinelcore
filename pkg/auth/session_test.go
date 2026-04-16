package auth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func testSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	client := redis.NewClient(opts)
	// Isolate test keyspace: flush DB. The test assumes a dedicated
	// redis DB number in TEST_REDIS_URL (e.g. redis://localhost:6379/15).
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("flushdb: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return NewSessionStoreFromClient(client)
}

func TestSessionStore_CreateAddsToUserIndex(t *testing.T) {
	s := testSessionStore(t)
	ctx := context.Background()

	if err := s.CreateSession(ctx, "jti-1", "user-A", time.Minute); err != nil {
		t.Fatal(err)
	}
	members, err := s.client.SMembers(ctx, "user:user-A:sessions").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0] != "jti-1" {
		t.Fatalf("members=%v, want [jti-1]", members)
	}
}

func TestSessionStore_RevokeSession_RemovesFromIndex(t *testing.T) {
	s := testSessionStore(t)
	ctx := context.Background()
	_ = s.CreateSession(ctx, "jti-1", "user-A", time.Minute)
	_ = s.CreateSession(ctx, "jti-2", "user-A", time.Minute)

	if err := s.RevokeSession(ctx, "jti-1"); err != nil {
		t.Fatal(err)
	}
	members, _ := s.client.SMembers(ctx, "user:user-A:sessions").Result()
	if len(members) != 1 || members[0] != "jti-2" {
		t.Fatalf("members=%v, want [jti-2]", members)
	}
}

func TestSessionStore_RevokeAllForUser_DrainsAllJTIs(t *testing.T) {
	s := testSessionStore(t)
	ctx := context.Background()

	_ = s.CreateSession(ctx, "jti-1", "user-A", time.Minute)
	_ = s.CreateSession(ctx, "jti-2", "user-A", time.Minute)
	_ = s.CreateSession(ctx, "jti-3", "user-B", time.Minute) // different user — must NOT be touched

	if err := s.RevokeAllForUser(ctx, "user-A"); err != nil {
		t.Fatal(err)
	}

	// All of user-A's sessions are gone.
	if active, _ := s.IsActive(ctx, "jti-1"); active {
		t.Error("jti-1 should be revoked")
	}
	if active, _ := s.IsActive(ctx, "jti-2"); active {
		t.Error("jti-2 should be revoked")
	}
	// user-B's session is untouched.
	if active, _ := s.IsActive(ctx, "jti-3"); !active {
		t.Error("jti-3 should still be active")
	}
	// user-A's index set is empty.
	n, _ := s.client.SCard(ctx, "user:user-A:sessions").Result()
	if n != 0 {
		t.Errorf("user-A set cardinality=%d, want 0", n)
	}
}

func TestSessionStore_RevokeAllForUser_EmptyUserIsNoOp(t *testing.T) {
	s := testSessionStore(t)
	if err := s.RevokeAllForUser(context.Background(), "user-does-not-exist"); err != nil {
		t.Fatalf("revoke on empty user should be no-op, got err=%v", err)
	}
}
