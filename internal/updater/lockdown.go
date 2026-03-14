package updater

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LockdownManager controls the update lockdown state via the database.
// When lockdown is active, all bundle imports are rejected.
type LockdownManager struct {
	pool *pgxpool.Pool
}

// NewLockdownManager creates a new LockdownManager backed by the given pool.
func NewLockdownManager(pool *pgxpool.Pool) *LockdownManager {
	return &LockdownManager{pool: pool}
}

// IsActive returns whether lockdown mode is enabled.
// It fails closed: any database error is treated as lockdown active.
func (l *LockdownManager) IsActive(ctx context.Context) (bool, error) {
	var value string
	err := l.pool.QueryRow(ctx,
		"SELECT value FROM updates.trust_state WHERE key = 'lockdown'",
	).Scan(&value)
	if err != nil {
		return true, err // fail closed
	}
	return value == "true", nil
}

// Enable activates lockdown mode and records a trust event.
func (l *LockdownManager) Enable(ctx context.Context, reason string) error {
	_, err := l.pool.Exec(ctx,
		"UPDATE updates.trust_state SET value = 'true', updated_at = now() WHERE key = 'lockdown'")
	if err != nil {
		return err
	}

	details, _ := json.Marshal(map[string]string{"reason": reason})
	_, err = l.pool.Exec(ctx,
		"INSERT INTO updates.trust_events (event_type, details) VALUES ('lockdown_enabled', $1)",
		details)
	return err
}

// Disable deactivates lockdown mode and records a trust event.
func (l *LockdownManager) Disable(ctx context.Context) error {
	_, err := l.pool.Exec(ctx,
		"UPDATE updates.trust_state SET value = 'false', updated_at = now() WHERE key = 'lockdown'")
	if err != nil {
		return err
	}

	details, _ := json.Marshal(map[string]string{})
	_, err = l.pool.Exec(ctx,
		"INSERT INTO updates.trust_events (event_type, details) VALUES ('lockdown_disabled', $1)",
		details)
	return err
}
