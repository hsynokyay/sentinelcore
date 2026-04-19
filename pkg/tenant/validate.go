package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ValidateProjectBelongsTo confirms project_id belongs to wantOrgID.
// Returns nil on success, ErrNotVisible if the project exists but
// belongs to a different tenant OR does not exist at all (collapsed to
// the same error so 404 is returned either way — see ErrNotVisible).
//
// This is the escape hatch for endpoints whose inputs include a
// project_id before the tenant RLS has a chance to filter (e.g. URL
// path params). Call this at the handler boundary; after a successful
// check, subsequent tenant.Tx calls can trust the ID.
func ValidateProjectBelongsTo(ctx context.Context, pool *pgxpool.Pool,
	projectID, wantOrgID string) error {

	if wantOrgID == "" {
		return ErrNoTenant
	}
	if projectID == "" {
		return fmt.Errorf("tenant: validate project: empty id")
	}

	return Tx(ctx, pool, wantOrgID, func(ctx context.Context, tx pgx.Tx) error {
		var ok bool
		// Same query pattern as internal handlers: a bare SELECT from
		// core.projects filtered by id. RLS kicks in via
		// app.current_org_id — if the row is not visible to this
		// tenant, EXISTS collapses to false and we return ErrNotVisible.
		err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM core.projects WHERE id = $1)`,
			projectID).Scan(&ok)
		if err != nil {
			return fmt.Errorf("tenant: validate project: %w", err)
		}
		if !ok {
			return ErrNotVisible
		}
		return nil
	})
}

// ValidateFindingBelongsTo is the same pattern for findings. RLS on
// findings.findings already filters by org_id so the EXISTS check
// is the authoritative ownership probe.
func ValidateFindingBelongsTo(ctx context.Context, pool *pgxpool.Pool,
	findingID, wantOrgID string) error {

	if wantOrgID == "" {
		return ErrNoTenant
	}
	if findingID == "" {
		return fmt.Errorf("tenant: validate finding: empty id")
	}
	return Tx(ctx, pool, wantOrgID, func(ctx context.Context, tx pgx.Tx) error {
		var ok bool
		err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM findings.findings WHERE id = $1)`,
			findingID).Scan(&ok)
		if err != nil {
			return fmt.Errorf("tenant: validate finding: %w", err)
		}
		if !ok {
			return ErrNotVisible
		}
		return nil
	})
}

// IsNotVisible is a convenience wrapper so handlers can write
//
//	if tenant.IsNotVisible(err) { return httperr.NotFound(...) }
//
// without importing errors and comparing against the sentinel directly.
func IsNotVisible(err error) bool { return errors.Is(err, ErrNotVisible) }
