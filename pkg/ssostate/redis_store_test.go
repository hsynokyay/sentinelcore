package ssostate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return New(c), mr
}

func randString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestStore_PutAndTake(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	orig := State{
		OrgID:        "o1",
		ProviderID:   "p1",
		PKCEVerifier: "v",
		Nonce:        "n",
		ReturnTo:     "/dashboard",
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}
	state := "s-" + randString(t, 16)
	if err := s.Put(ctx, state, orig); err != nil {
		t.Fatal(err)
	}
	got, err := s.Take(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if got.OrgID != orig.OrgID || got.PKCEVerifier != orig.PKCEVerifier || got.Nonce != orig.Nonce {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, orig)
	}
	// Second Take must fail — single-use.
	if _, err := s.Take(ctx, state); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("second Take must be ErrStateNotFound, got %v", err)
	}
}

func TestStore_Expires(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	state := "s-" + randString(t, 16)
	if err := s.PutWithTTL(ctx, state, State{OrgID: "o"}, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// Fast-forward miniredis past TTL.
	mr.FastForward(200 * time.Millisecond)
	if _, err := s.Take(ctx, state); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("expired state should be absent, got %v", err)
	}
}

func TestStore_WrongState(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Take(context.Background(), "nonexistent"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("wrong state should be ErrStateNotFound, got %v", err)
	}
}

func TestStore_EmptyToken(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, "", State{}); err == nil {
		t.Fatal("Put with empty token should fail")
	}
	if _, err := s.Take(ctx, ""); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("Take with empty token should be ErrStateNotFound, got %v", err)
	}
}
