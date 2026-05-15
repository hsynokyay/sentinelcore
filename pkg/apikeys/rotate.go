package apikeys

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RotateResult bundles Rotate's output so the handler can audit both
// old and new prefix without a separate pre-fetch (which would introduce
// a TOCTOU window against concurrent rotates).
type RotateResult struct {
	CreateResult        // embedded: ID, PlainText, Prefix (new), Name, Scopes, ExpiresAt, IsServiceAccount, Description
	OldPrefix    string // prefix before this rotation, captured atomically
}

// Rotate replaces the key's plaintext in a single atomic UPDATE. The old
// plaintext stops working immediately — there is no grace window where
// both tokens are valid. Returns both old and new prefix (so the handler
// can audit without a separate pre-fetch TOCTOU).
//
// Tenant isolation via org_id predicate. Fails if key is revoked or
// belongs to a different org. Uses a CTE to capture the old prefix in
// the same statement as the UPDATE — atomic, no race.
func Rotate(ctx context.Context, pool *pgxpool.Pool, keyID, orgID string) (*RotateResult, error) {
	if keyID == "" || orgID == "" {
		return nil, fmt.Errorf("keyID and orgID are required")
	}

	raw := Generate()
	hash := Hash(raw)
	prefix := PrefixOf(raw)
	now := time.Now()

	var result RotateResult
	err := pool.QueryRow(ctx, `
        WITH old AS (
            SELECT prefix FROM core.api_keys
            WHERE id = $4 AND org_id = $5
        )
        UPDATE core.api_keys k
        SET key_hash   = $1,
            prefix     = $2,
            rotated_at = $3
        FROM old
        WHERE k.id = $4
          AND k.org_id = $5
          AND k.revoked = false
        RETURNING k.id, k.name, COALESCE(k.description, ''), k.scopes, k.expires_at, k.is_service_account, old.prefix
    `, hash, prefix, now, keyID, orgID).Scan(
		&result.ID, &result.Name, &result.Description, &result.Scopes, &result.ExpiresAt, &result.IsServiceAccount,
		&result.OldPrefix,
	)
	if err != nil {
		return nil, fmt.Errorf("rotate api_key: %w (key not found, revoked, or cross-tenant)", err)
	}

	result.PlainText = raw
	result.Prefix = prefix
	return &result, nil
}
