package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LoginEvent is one row of auth.sso_login_events exposed to the admin
// history API. claims_redacted is emitted as raw JSON (map[string]any)
// so the UI can render it without a second decode.
type LoginEvent struct {
	ID             int64          `json:"id"`
	ProviderID     string         `json:"provider_id"`
	OccurredAt     time.Time      `json:"occurred_at"`
	Outcome        string         `json:"outcome"`
	ErrorCode      string         `json:"error_code,omitempty"`
	ExternalID     string         `json:"external_id,omitempty"`
	Email          string         `json:"email,omitempty"`
	RoleGranted    string         `json:"role_granted,omitempty"`
	ClaimsRedacted map[string]any `json:"claims_redacted,omitempty"`
	IPAddress      string         `json:"ip_address,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
}

// EventStore reads auth.sso_login_events for the admin diagnostics UI.
// RLS on the table uses the provider_id → oidc_providers → org_id chain,
// so the caller MUST have set app.current_org_id before reading (the
// handler does this via the transaction it already uses for tenant
// resolution).
type EventStore struct {
	pool *pgxpool.Pool
}

func NewEventStore(pool *pgxpool.Pool) *EventStore {
	return &EventStore{pool: pool}
}

// ListByProvider returns the most recent `limit` events for a provider,
// newest first. limit is clamped to [1, 200]; the retention trigger caps
// the underlying table at 500 rows per provider anyway.
func (s *EventStore) ListByProvider(ctx context.Context, providerID string, limit int) ([]LoginEvent, error) {
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider_id::text, occurred_at, outcome,
		       COALESCE(error_code, ''), COALESCE(external_id, ''),
		       COALESCE(email, ''), COALESCE(role_granted, ''),
		       COALESCE(claims_redacted, '{}'::jsonb),
		       COALESCE(host(ip_address), ''),
		       COALESCE(user_agent, '')
		FROM auth.sso_login_events
		WHERE provider_id = $1
		ORDER BY occurred_at DESC, id DESC
		LIMIT $2
	`, providerID, limit)
	if err != nil {
		return nil, fmt.Errorf("list sso events: %w", err)
	}
	defer rows.Close()
	var out []LoginEvent
	for rows.Next() {
		var e LoginEvent
		var claimsRaw []byte
		if err := rows.Scan(&e.ID, &e.ProviderID, &e.OccurredAt, &e.Outcome,
			&e.ErrorCode, &e.ExternalID, &e.Email, &e.RoleGranted,
			&claimsRaw, &e.IPAddress, &e.UserAgent); err != nil {
			return nil, err
		}
		if len(claimsRaw) > 0 && string(claimsRaw) != "{}" {
			_ = json.Unmarshal(claimsRaw, &e.ClaimsRedacted)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

