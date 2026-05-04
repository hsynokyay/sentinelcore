package bundles

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Approve sets status to 'approved' and stamps approved_by_user_id +
// approved_at + adjusts expires_at to created_at + ttl. The Postgres
// 4-eyes trigger enforces reviewerUserID != recorder.
func (s *PostgresStore) Approve(ctx context.Context, id, reviewerUserID string, ttlSeconds int) error {
	if ttlSeconds <= 0 {
		ttlSeconds = 86400
	}
	if ttlSeconds > 7*86400 {
		return fmt.Errorf("approve: ttl_seconds exceeds 7 days")
	}
	expiresAt := s.now().Add(time.Duration(ttlSeconds) * time.Second)
	tag, err := s.pool.Exec(ctx, `
        UPDATE dast_auth_bundles
           SET status = 'approved',
               approved_by_user_id = $2,
               approved_at = now(),
               expires_at = $3,
               ttl_seconds = $4
         WHERE id = $1 AND status = 'pending_review'`,
		id, reviewerUserID, expiresAt, ttlSeconds)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrBundleNotFound
	}
	return nil
}

// Reject moves a pending_review bundle to revoked status with a reason.
func (s *PostgresStore) Reject(ctx context.Context, id, reviewerUserID, reason string) error {
	tag, err := s.pool.Exec(ctx, `
        UPDATE dast_auth_bundles
           SET status = 'revoked',
               revoked_at = now(),
               wrapped_dek = '\x00'::bytea,
               metadata_jsonb = metadata_jsonb || jsonb_build_object(
                   'reject_reason', $3::text,
                   'rejected_by_user_id', $2::text)
         WHERE id = $1 AND status = 'pending_review'`,
		id, reviewerUserID, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrBundleNotFound
	}
	return nil
}

// ListPending returns BundleSummary for bundles in pending_review status.
func (s *PostgresStore) ListPending(ctx context.Context, customerID string, offset, limit int) ([]*BundleSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	var rows pgx.Rows
	var err error
	if customerID == "" {
		rows, err = s.pool.Query(ctx, `
            SELECT id, customer_id, project_id, target_host, type, status,
                   created_by_user_id, created_at, expires_at, use_count, metadata_jsonb
              FROM dast_auth_bundles
             WHERE status = 'pending_review'
             ORDER BY created_at ASC
             OFFSET $1 LIMIT $2`, offset, limit)
	} else {
		rows, err = s.pool.Query(ctx, `
            SELECT id, customer_id, project_id, target_host, type, status,
                   created_by_user_id, created_at, expires_at, use_count, metadata_jsonb
              FROM dast_auth_bundles
             WHERE status = 'pending_review' AND customer_id = $1
             ORDER BY created_at ASC
             OFFSET $2 LIMIT $3`, customerID, offset, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list pending: %w", err)
	}
	defer rows.Close()

	var out []*BundleSummary
	for rows.Next() {
		var b BundleSummary
		if err := rows.Scan(&b.ID, &b.CustomerID, &b.ProjectID, &b.TargetHost, &b.Type, &b.Status,
			&b.CreatedByUserID, &b.CreatedAt, &b.ExpiresAt, &b.UseCount, &b.MetadataJSONB); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

// ErrApprovalSelfRecorder is the user-friendly error when the 4-eyes trigger fires.
var ErrApprovalSelfRecorder = errors.New("approval rejected by 4-eyes: recorder cannot approve own recording")
