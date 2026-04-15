package policy

import (
	"context"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Cache holds the role→permission matrix in memory. Loaded at startup,
// refreshed via pg_notify when an admin mutates role_permissions.
//
// Readers acquire RLock; full reload swaps the map atomically under Lock,
// so readers never see a partial state.
type Cache struct {
	mu       sync.RWMutex
	matrix   map[string]map[string]struct{} // role_id → set of permission_id
	allPerms map[string]struct{}             // set of every known permission_id
	version  int64                           // incremented each Reload
}

// NewCache returns an empty cache. Call Reload before serving traffic.
func NewCache() *Cache {
	return &Cache{
		matrix:   make(map[string]map[string]struct{}),
		allPerms: make(map[string]struct{}),
	}
}

// Can returns true iff the role has the permission. Safe for concurrent use.
// Returns false for unknown roles or permissions.
func (c *Cache) Can(role, perm string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	perms, ok := c.matrix[role]
	if !ok {
		return false
	}
	_, ok = perms[perm]
	return ok
}

// HasPermission returns true iff perm exists in the permissions catalog
// (regardless of any role). Used at key-creation time to validate scopes.
func (c *Cache) HasPermission(perm string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.allPerms[perm]
	return ok
}

// Reload replaces the in-memory matrix from the database in a single
// atomic swap. Safe to call concurrently with readers.
func (c *Cache) Reload(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT rp.role_id, rp.permission_id
		FROM auth.role_permissions rp
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	newMatrix := make(map[string]map[string]struct{})
	for rows.Next() {
		var roleID, permID string
		if err := rows.Scan(&roleID, &permID); err != nil {
			return err
		}
		if _, ok := newMatrix[roleID]; !ok {
			newMatrix[roleID] = make(map[string]struct{})
		}
		newMatrix[roleID][permID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Load the full permissions catalog separately (there may be permissions
	// with zero role assignments that we still want to recognise).
	permRows, err := pool.Query(ctx, `SELECT id FROM auth.permissions`)
	if err != nil {
		return err
	}
	defer permRows.Close()
	newAll := make(map[string]struct{})
	for permRows.Next() {
		var id string
		if err := permRows.Scan(&id); err != nil {
			return err
		}
		newAll[id] = struct{}{}
	}
	if err := permRows.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	c.matrix = newMatrix
	c.allPerms = newAll
	c.version++
	c.mu.Unlock()
	return nil
}

// Version returns the current reload counter. Used in tests.
func (c *Cache) Version() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}
