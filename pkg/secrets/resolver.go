// Package secrets provides a single interface to every long-lived
// platform secret. Two implementations:
//
//   EnvResolver   — reads OS env vars via a deterministic path→name map.
//                   Used in dev, CI, and the transitional production
//                   deployment where env-file secrets are ok.
//   VaultResolver — KV v2 against HashiCorp Vault. Not yet in prod;
//                   scaffolded so the handler + worker layers can
//                   already depend on Resolver.
//
// The split lets us migrate a service to Vault by changing ONE env var
// (SC_SECRET_BACKEND=vault) without touching the caller's code.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when a Resolver implementation cannot find a
// secret at the requested path. Callers errors.Is-check this so a
// missing secret surfaces the same code path regardless of backend.
var ErrNotFound = errors.New("secrets: not found")

// Resolver fetches decrypted material for a logical secret path.
// Implementations are safe for concurrent use.
type Resolver interface {
	// Get returns raw bytes for a path (e.g. binary AES keys).
	Get(ctx context.Context, path string) ([]byte, error)

	// GetString is the ergonomic shortcut for ASCII secrets (passwords,
	// tokens). Equivalent to Get followed by string(). Implementations
	// validate UTF-8.
	GetString(ctx context.Context, path string) (string, error)

	// Version returns a monotonic counter the rotation orchestrator uses
	// to invalidate caches. -1 when the backend does not expose versions.
	Version(ctx context.Context, path string) (int, error)

	// Backend is a short human-readable tag ("env", "vault", "file")
	// surfaced in startup logs so operators can see which resolver is
	// active without inspecting env vars.
	Backend() string
}

// DefaultResolver picks an implementation from SC_SECRET_BACKEND.
// Unset or "env" → EnvResolver (the current production default).
// "vault" → VaultResolver (unimplemented; panics for now).
// "file"  → FileResolver (dev convenience; reads ./secrets.local).
func DefaultResolver() (Resolver, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SC_SECRET_BACKEND"))) {
	case "", "env":
		return NewEnvResolver(), nil
	case "file":
		return NewFileResolver(envOrDefault("SC_SECRET_FILE", "./secrets.local"))
	case "vault":
		// VaultResolver is a stub today. The plan's Wave 3 wires this
		// up; until then we refuse to start with backend=vault.
		return nil, errors.New("secrets: vault backend not yet implemented")
	default:
		return nil, fmt.Errorf("secrets: unknown SC_SECRET_BACKEND %q",
			os.Getenv("SC_SECRET_BACKEND"))
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// cachedResolver wraps a Resolver with a tiny TTL cache so hot-path
// readers (audit writer, API-key verifier) don't hammer the backend.
// 60-second TTL matches the plan's rotation policy: a new key version
// is always picked up within one minute.
type cachedResolver struct {
	inner Resolver
	mu    sync.RWMutex
	cache map[string]cacheEntry
	ttl   int64 // seconds
}

type cacheEntry struct {
	val     []byte
	version int
	stored  int64 // unix seconds
}

// NewCachedResolver returns a Resolver that memoises Get + Version for
// ttlSeconds. Calls with ttlSeconds <= 0 use a 60s default.
func NewCachedResolver(inner Resolver, ttlSeconds int64) Resolver {
	if ttlSeconds <= 0 {
		ttlSeconds = 60
	}
	return &cachedResolver{
		inner: inner,
		cache: map[string]cacheEntry{},
		ttl:   ttlSeconds,
	}
}

func (c *cachedResolver) Backend() string { return c.inner.Backend() + "+cache" }

func (c *cachedResolver) get(ctx context.Context, path string) (cacheEntry, error) {
	now := nowSeconds()
	c.mu.RLock()
	if e, ok := c.cache[path]; ok && now-e.stored < c.ttl {
		c.mu.RUnlock()
		return e, nil
	}
	c.mu.RUnlock()

	val, err := c.inner.Get(ctx, path)
	if err != nil {
		return cacheEntry{}, err
	}
	ver, _ := c.inner.Version(ctx, path) // -1 fine
	entry := cacheEntry{val: val, version: ver, stored: now}

	c.mu.Lock()
	c.cache[path] = entry
	c.mu.Unlock()
	return entry, nil
}

func (c *cachedResolver) Get(ctx context.Context, path string) ([]byte, error) {
	e, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	// Defensive copy — callers must not mutate the cache.
	out := make([]byte, len(e.val))
	copy(out, e.val)
	return out, nil
}

func (c *cachedResolver) GetString(ctx context.Context, path string) (string, error) {
	b, err := c.Get(ctx, path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *cachedResolver) Version(ctx context.Context, path string) (int, error) {
	e, err := c.get(ctx, path)
	if err != nil {
		return -1, err
	}
	return e.version, nil
}

// nowSeconds is a var so tests can freeze time.
var nowSeconds = func() int64 { return time.Now().Unix() }
