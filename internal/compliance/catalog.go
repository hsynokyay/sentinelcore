package compliance

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrBuiltinReadOnly is returned by mutation paths when the caller tries
// to modify a row that is part of a built-in catalog (org_id IS NULL).
// Handlers map this to HTTP 403.
var ErrBuiltinReadOnly = errors.New("built-in catalogs are read-only")

// ListCatalogs returns every catalog visible to the caller's org, i.e.
// every built-in plus every tenant-owned catalog whose org_id matches.
// Rows come back ordered by code, version for stable rendering.
func ListCatalogs(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) ([]Catalog, error) {
	const q = `
        SELECT id, org_id, code, name, version, COALESCE(description, ''), is_builtin
        FROM governance.control_catalogs
        WHERE org_id IS NULL OR org_id = $1
        ORDER BY code, version
    `
	rows, err := pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("query catalogs: %w", err)
	}
	defer rows.Close()
	var out []Catalog
	for rows.Next() {
		var c Catalog
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Code, &c.Name, &c.Version, &c.Description, &c.IsBuiltin); err != nil {
			return nil, fmt.Errorf("scan catalog: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListItems returns every item belonging to the given catalog. RLS keeps
// callers from peeking into other tenants' custom items; built-in items
// are visible to all orgs.
func ListItems(ctx context.Context, pool *pgxpool.Pool, orgID, catalogID uuid.UUID) ([]Item, error) {
	const q = `
        SELECT i.id, i.catalog_id, i.control_id, i.title, COALESCE(i.description, '')
        FROM governance.control_items i
        JOIN governance.control_catalogs c ON c.id = i.catalog_id
        WHERE i.catalog_id = $1 AND (c.org_id IS NULL OR c.org_id = $2)
        ORDER BY i.control_id
    `
	rows, err := pool.Query(ctx, q, catalogID, orgID)
	if err != nil {
		return nil, fmt.Errorf("query items: %w", err)
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.CatalogID, &it.ControlID, &it.Title, &it.Description); err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ListMappings returns the merged built-in + tenant mapping set, optionally
// filtered by a (sourceKind, sourceCode) pair. Pass empty strings to skip
// the filter and see everything visible.
func ListMappings(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, sourceKind, sourceCode string) ([]Mapping, error) {
	q := `
        SELECT id, org_id, source_kind, source_code, target_control_id,
               confidence, COALESCE(source_version, '')
        FROM governance.control_mappings
        WHERE (org_id IS NULL OR org_id = $1)
    `
	args := []any{orgID}
	if sourceKind != "" {
		args = append(args, sourceKind)
		q += fmt.Sprintf(" AND source_kind = $%d", len(args))
	}
	if sourceCode != "" {
		args = append(args, sourceCode)
		q += fmt.Sprintf(" AND source_code = $%d", len(args))
	}
	q += " ORDER BY source_kind, source_code, confidence"

	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query mappings: %w", err)
	}
	defer rows.Close()
	var out []Mapping
	for rows.Next() {
		var m Mapping
		if err := rows.Scan(&m.ID, &m.OrgID, &m.SourceKind, &m.SourceCode, &m.TargetControlID,
			&m.Confidence, &m.SourceVersion); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CreateCatalog inserts a tenant-owned catalog. Built-in seeding is the
// migration's job; org callers always go through this path which forces
// is_builtin=false and stamps org_id.
func CreateCatalog(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, code, name, version, description string) (Catalog, error) {
	if code == "" || name == "" || version == "" {
		return Catalog{}, errors.New("code, name, version are required")
	}
	c := Catalog{OrgID: &orgID, Code: code, Name: name, Version: version, Description: description, IsBuiltin: false}
	const q = `
        INSERT INTO governance.control_catalogs (org_id, code, name, version, description, is_builtin)
        VALUES ($1, $2, $3, $4, NULLIF($5, ''), false)
        RETURNING id
    `
	if err := pool.QueryRow(ctx, q, orgID, code, name, version, description).Scan(&c.ID); err != nil {
		return Catalog{}, fmt.Errorf("insert catalog: %w", err)
	}
	return c, nil
}

// CreateItem inserts an item under a tenant-owned catalog. Returns
// ErrBuiltinReadOnly if the caller tries to attach an item to a built-in
// catalog or one belonging to a different org.
func CreateItem(ctx context.Context, pool *pgxpool.Pool, orgID, catalogID uuid.UUID, controlID, title, description string) (Item, error) {
	if controlID == "" || title == "" {
		return Item{}, errors.New("control_id, title are required")
	}
	owner, err := catalogOwner(ctx, pool, catalogID)
	if err != nil {
		return Item{}, err
	}
	if owner == nil || *owner != orgID {
		return Item{}, ErrBuiltinReadOnly
	}
	it := Item{CatalogID: catalogID, ControlID: controlID, Title: title, Description: description}
	const q = `
        INSERT INTO governance.control_items (catalog_id, control_id, title, description)
        VALUES ($1, $2, $3, NULLIF($4, ''))
        RETURNING id
    `
	if err := pool.QueryRow(ctx, q, catalogID, controlID, title, description).Scan(&it.ID); err != nil {
		return Item{}, fmt.Errorf("insert item: %w", err)
	}
	return it, nil
}

// CreateMapping inserts a tenant-owned mapping (always confidence='custom').
// The target item must belong to a catalog the caller owns OR to a built-in
// catalog (so a tenant can map "CWE-79 → OWASP A03" with their own annotation).
func CreateMapping(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, sourceKind, sourceCode string, targetItemID uuid.UUID, sourceVersion string) (Mapping, error) {
	if sourceKind == "" || sourceCode == "" {
		return Mapping{}, errors.New("source_kind, source_code are required")
	}
	switch sourceKind {
	case "cwe", "owasp", "internal":
	default:
		return Mapping{}, errors.New("source_kind must be one of cwe|owasp|internal")
	}
	// Item must be visible to the caller (built-in or owned).
	owner, err := itemCatalogOwner(ctx, pool, targetItemID)
	if err != nil {
		return Mapping{}, err
	}
	if owner != nil && *owner != orgID {
		return Mapping{}, ErrBuiltinReadOnly
	}
	m := Mapping{
		OrgID:           &orgID,
		SourceKind:      sourceKind,
		SourceCode:      sourceCode,
		TargetControlID: targetItemID,
		Confidence:      "custom",
		SourceVersion:   sourceVersion,
	}
	const q = `
        INSERT INTO governance.control_mappings
            (org_id, source_kind, source_code, target_control_id, confidence, source_version)
        VALUES ($1, $2, $3, $4, 'custom', NULLIF($5, ''))
        RETURNING id
    `
	if err := pool.QueryRow(ctx, q, orgID, sourceKind, sourceCode, targetItemID, sourceVersion).Scan(&m.ID); err != nil {
		return Mapping{}, fmt.Errorf("insert mapping: %w", err)
	}
	return m, nil
}

// DeleteMapping removes a tenant-owned mapping. Built-in mappings (org_id IS
// NULL) cannot be deleted — the call returns ErrBuiltinReadOnly.
func DeleteMapping(ctx context.Context, pool *pgxpool.Pool, orgID, mappingID uuid.UUID) error {
	var owner *uuid.UUID
	err := pool.QueryRow(ctx, `SELECT org_id FROM governance.control_mappings WHERE id = $1`, mappingID).Scan(&owner)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return pgx.ErrNoRows
		}
		return fmt.Errorf("lookup mapping: %w", err)
	}
	if owner == nil || *owner != orgID {
		return ErrBuiltinReadOnly
	}
	if _, err := pool.Exec(ctx, `DELETE FROM governance.control_mappings WHERE id = $1 AND org_id = $2`, mappingID, orgID); err != nil {
		return fmt.Errorf("delete mapping: %w", err)
	}
	return nil
}

// catalogOwner returns the org_id of the catalog (or nil for built-ins).
func catalogOwner(ctx context.Context, pool *pgxpool.Pool, catalogID uuid.UUID) (*uuid.UUID, error) {
	var owner *uuid.UUID
	err := pool.QueryRow(ctx, `SELECT org_id FROM governance.control_catalogs WHERE id = $1`, catalogID).Scan(&owner)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgx.ErrNoRows
		}
		return nil, fmt.Errorf("lookup catalog owner: %w", err)
	}
	return owner, nil
}

// itemCatalogOwner returns the org_id of the catalog the item belongs to.
func itemCatalogOwner(ctx context.Context, pool *pgxpool.Pool, itemID uuid.UUID) (*uuid.UUID, error) {
	var owner *uuid.UUID
	err := pool.QueryRow(ctx, `
        SELECT c.org_id
        FROM governance.control_items i
        JOIN governance.control_catalogs c ON c.id = i.catalog_id
        WHERE i.id = $1
    `, itemID).Scan(&owner)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgx.ErrNoRows
		}
		return nil, fmt.Errorf("lookup item owner: %w", err)
	}
	return owner, nil
}
