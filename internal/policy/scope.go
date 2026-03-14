package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ValidateScanTarget checks if a scan target is verified and not expired.
func ValidateScanTarget(ctx context.Context, pool *pgxpool.Pool, targetID string) error {
	var verifiedAt *time.Time
	var expiresAt *time.Time

	err := pool.QueryRow(ctx,
		`SELECT tv.verified_at, tv.expires_at
		 FROM core.target_verifications tv
		 WHERE tv.target_id = $1 AND tv.status = 'verified'
		 ORDER BY tv.verified_at DESC LIMIT 1`, targetID).Scan(&verifiedAt, &expiresAt)

	if err != nil {
		return fmt.Errorf("scan target %s is not verified", targetID)
	}
	if verifiedAt == nil {
		return fmt.Errorf("scan target %s has no verification", targetID)
	}
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return fmt.Errorf("scan target %s verification expired at %s", targetID, expiresAt)
	}
	return nil
}
