package compliance

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ResolveControls returns every ControlRef that applies for the given
// CWE id under the calling organization. Built-in (org_id IS NULL)
// mappings always merge with the tenant's custom (org_id = orgID)
// mappings so analysts always see the normative control set plus any
// internal additions.
//
// Ordering is deterministic: confidence priority (custom < normative <
// derived), then catalog code, then control id. The caller can rely on
// this for stable SARIF/Markdown output and snapshot diffs.
func ResolveControls(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, cweID int) ([]ControlRef, error) {
	const q = `
        SELECT c.code, c.name, i.control_id, i.title,
               m.confidence, m.source_kind, m.source_code
        FROM governance.control_mappings m
        JOIN governance.control_items i ON i.id = m.target_control_id
        JOIN governance.control_catalogs c ON c.id = i.catalog_id
        WHERE m.source_kind = 'cwe' AND m.source_code = $1
          AND (m.org_id IS NULL OR m.org_id = $2)
        ORDER BY
            CASE m.confidence
                WHEN 'custom' THEN 0
                WHEN 'normative' THEN 1
                ELSE 2
            END,
            c.code,
            i.control_id
    `
	rows, err := pool.Query(ctx, q, fmt.Sprintf("CWE-%d", cweID), orgID)
	if err != nil {
		return nil, fmt.Errorf("query control mappings: %w", err)
	}
	defer rows.Close()

	var out []ControlRef
	for rows.Next() {
		var r ControlRef
		if err := rows.Scan(&r.CatalogCode, &r.CatalogName, &r.ControlID, &r.Title,
			&r.Confidence, &r.SourceKind, &r.SourceCode); err != nil {
			return nil, fmt.Errorf("scan control mapping: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate control mappings: %w", err)
	}
	return out, nil
}
