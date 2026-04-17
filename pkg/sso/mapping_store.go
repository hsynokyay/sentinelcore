package sso

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StoredMapping is one row of auth.oidc_group_mappings.
type StoredMapping struct {
	ID         string
	ProviderID string
	Group      string
	Role       string
	Priority   int
}

// ErrMappingNotFound signals a 404 for CRUD endpoints.
var ErrMappingNotFound = errors.New("sso: group mapping not found")

// MappingStore reads/writes auth.oidc_group_mappings.
// RLS on the table is provider_id-scoped via a join to oidc_providers, so
// the caller MUST have set app.current_org_id for the session/transaction
// before invoking any method except ListForResolver (the resolver runs
// inside the callback flow which has just established the org).
type MappingStore struct {
	pool *pgxpool.Pool
}

func NewMappingStore(pool *pgxpool.Pool) *MappingStore {
	return &MappingStore{pool: pool}
}

// List returns mappings for the admin UI, ordered by priority ASC, role ASC.
func (s *MappingStore) List(ctx context.Context, providerID string) ([]StoredMapping, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, provider_id::text, group_claim, role_id, priority
		FROM auth.oidc_group_mappings
		WHERE provider_id = $1
		ORDER BY priority ASC, role_id ASC
	`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredMapping
	for rows.Next() {
		var m StoredMapping
		if err := rows.Scan(&m.ID, &m.ProviderID, &m.Group, &m.Role, &m.Priority); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListForResolver returns GroupMapping (the struct ResolveRole consumes).
// Called by the callback handler during JIT provisioning.
func (s *MappingStore) ListForResolver(ctx context.Context, providerID string) ([]GroupMapping, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT group_claim, role_id, priority
		FROM auth.oidc_group_mappings
		WHERE provider_id = $1
	`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMapping
	for rows.Next() {
		var m GroupMapping
		if err := rows.Scan(&m.Group, &m.Role, &m.Priority); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Create upserts a mapping for (provider_id, group_claim).
// Same group → later call updates role and priority.
func (s *MappingStore) Create(ctx context.Context, providerID, group, role string, priority int) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO auth.oidc_group_mappings (provider_id, group_claim, role_id, priority)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (provider_id, group_claim) DO UPDATE
		    SET role_id = EXCLUDED.role_id, priority = EXCLUDED.priority
		RETURNING id::text
	`, providerID, group, role, priority).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert mapping: %w", err)
	}
	return id, nil
}

// Delete removes a mapping by (id, provider_id) — the provider_id check
// prevents cross-provider deletes even if the caller guesses an ID.
func (s *MappingStore) Delete(ctx context.Context, providerID, id string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM auth.oidc_group_mappings WHERE id = $1 AND provider_id = $2`,
		id, providerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMappingNotFound
	}
	return nil
}
