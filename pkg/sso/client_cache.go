package sso

import (
	"context"
	"sync"
)

// ClientCache is a per-provider memoised cache of OIDC Clients.
//
// Construction of a Client performs discovery + JWKS fetch — ~2 HTTPS
// round-trips. We memoise per provider_id so login requests don't
// reimburse that cost on every hit. Callers invalidate a cached entry
// after the provider is updated (issuer / client_id / scopes change).
type ClientCache struct {
	mu      sync.Mutex
	clients map[string]*Client
}

func NewClientCache() *ClientCache {
	return &ClientCache{clients: make(map[string]*Client)}
}

// GetOrCreate returns the cached Client for a providerID, constructing
// one via New(ctx, cfg) on cache miss. Thread-safe.
func (c *ClientCache) GetOrCreate(ctx context.Context, providerID string, cfg Config) (*Client, error) {
	c.mu.Lock()
	if existing, ok := c.clients[providerID]; ok {
		c.mu.Unlock()
		return existing, nil
	}
	c.mu.Unlock()

	// Discovery happens outside the lock so parallel cache-misses don't
	// serialize behind the slowest provider.
	cli, err := New(ctx, cfg)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check: another goroutine may have populated while we were
	// running discovery. Prefer the existing instance for consistency.
	if existing, ok := c.clients[providerID]; ok {
		return existing, nil
	}
	c.clients[providerID] = cli
	return cli, nil
}

// Invalidate drops the cached Client for a providerID so the next
// GetOrCreate re-runs discovery. Safe to call on unknown IDs.
func (c *ClientCache) Invalidate(providerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.clients, providerID)
}
