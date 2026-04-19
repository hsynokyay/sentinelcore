package governance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

// CreateRetentionRecord inserts a new retention record. If a record for the
// same (resource_type, resource_id) already exists the insert is silently
// skipped via ON CONFLICT DO NOTHING. Cross-org (no RLS).
func CreateRetentionRecord(ctx context.Context, pool *pgxpool.Pool, rec *RetentionRecord) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	if rec == nil {
		return errors.New("governance: retention record is nil")
	}

	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	if rec.Lifecycle == "" {
		rec.Lifecycle = "active"
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, `
		INSERT INTO governance.retention_records (
			id, org_id, resource_type, resource_id, lifecycle,
			retention_days, expires_at, archived_at, purge_after,
			purged_at, legal_hold, legal_hold_by, legal_hold_reason, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (resource_type, resource_id) DO NOTHING`,
		rec.ID, rec.OrgID, rec.ResourceType, rec.ResourceID, rec.Lifecycle,
		rec.RetentionDays, rec.ExpiresAt, rec.ArchivedAt, rec.PurgeAfter,
		rec.PurgedAt, rec.LegalHold, rec.LegalHoldBy, rec.LegalHoldReason, rec.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("governance: create retention record: %w", err)
	}
	return nil
}

// TransitionToArchived moves active records whose expires_at has passed into
// the 'archived' lifecycle state. Cross-org (no RLS).
func TransitionToArchived(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int, error) {
	if pool == nil {
		return 0, errors.New("governance: pool is nil")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	tag, err := conn.Exec(ctx, `
		UPDATE governance.retention_records
		   SET lifecycle = 'archived',
		       archived_at = $1
		 WHERE lifecycle = 'active'
		   AND expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("governance: transition to archived: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// TransitionToPurgePending moves archived records whose purge_after has passed
// into the 'purge_pending' lifecycle state. Cross-org (no RLS).
func TransitionToPurgePending(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int, error) {
	if pool == nil {
		return 0, errors.New("governance: pool is nil")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	tag, err := conn.Exec(ctx, `
		UPDATE governance.retention_records
		   SET lifecycle = 'purge_pending'
		 WHERE lifecycle = 'archived'
		   AND purge_after < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("governance: transition to purge pending: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// PurgeRecords marks purge_pending records as 'purged'. Records with
// legal_hold=true are unconditionally skipped — this is a hard safety
// requirement. Cross-org (no RLS).
func PurgeRecords(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int, error) {
	if pool == nil {
		return 0, errors.New("governance: pool is nil")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	// Select purge_pending records that are NOT under legal hold.
	rows, err := conn.Query(ctx, `
		SELECT id FROM governance.retention_records
		 WHERE lifecycle = 'purge_pending'
		   AND legal_hold = false`)
	if err != nil {
		return 0, fmt.Errorf("governance: purge select: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			return 0, fmt.Errorf("governance: purge scan: %w", scanErr)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("governance: purge rows: %w", err)
	}

	if len(ids) == 0 {
		return 0, nil
	}

	// Mark each eligible record as purged.
	count := 0
	for _, id := range ids {
		tag, execErr := conn.Exec(ctx, `
			UPDATE governance.retention_records
			   SET lifecycle = 'purged',
			       purged_at = $1
			 WHERE id = $2
			   AND legal_hold = false`, now, id)
		if execErr != nil {
			return count, fmt.Errorf("governance: purge record %s: %w", id, execErr)
		}
		count += int(tag.RowsAffected())
	}
	return count, nil
}

// SetLegalHold enables or disables legal hold on a retention record.
// Uses RLS — must be called with the acting user's identity.
func SetLegalHold(ctx context.Context, pool *pgxpool.Pool, userID, orgID, resourceType, resourceID string, hold bool, reason string) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}

	return tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE governance.retention_records
			   SET legal_hold = $1,
			       legal_hold_by = $2,
			       legal_hold_reason = $3
			 WHERE resource_type = $4
			   AND resource_id = $5`,
			hold, userID, reason, resourceType, resourceID,
		)
		return err
	})
}

// GetRetentionStats returns a count of retention records grouped by
// resource_type and lifecycle. Uses RLS.
func GetRetentionStats(ctx context.Context, pool *pgxpool.Pool, userID, orgID string) (map[string]map[string]int, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}

	result := make(map[string]map[string]int)

	err := tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx, `
			SELECT resource_type, lifecycle, COUNT(*)
			  FROM governance.retention_records
			 GROUP BY resource_type, lifecycle`)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()

		for rows.Next() {
			var resourceType, lifecycle string
			var count int
			if scanErr := rows.Scan(&resourceType, &lifecycle, &count); scanErr != nil {
				return fmt.Errorf("governance: scan retention stats: %w", scanErr)
			}
			if result[resourceType] == nil {
				result[resourceType] = make(map[string]int)
			}
			result[resourceType][lifecycle] = count
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("governance: get retention stats: %w", err)
	}
	return result, nil
}
