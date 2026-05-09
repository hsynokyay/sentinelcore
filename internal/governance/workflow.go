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

// LegacyCreateApprovalRequest is the Phase-4 entrypoint for creating an
// approval request. New code should call CreateApprovalRequest (decisions.go)
// which carries the two-person columns and returns the inserted row.
func LegacyCreateApprovalRequest(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, req *ApprovalRequest) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	if req == nil {
		return errors.New("governance: approval request is nil")
	}

	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	req.OrgID = orgID
	req.RequestedBy = userID
	req.Status = "pending"
	req.CreatedAt = time.Now()
	expires := req.CreatedAt.Add(7 * 24 * time.Hour)
	req.ExpiresAt = &expires

	return tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO governance.approval_requests (
				id, org_id, team_id, request_type, resource_type,
				resource_id, requested_by, reason, status, expires_at, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			req.ID, req.OrgID, req.TeamID, req.RequestType, req.ResourceType,
			req.ResourceID, req.RequestedBy, req.Reason, req.Status, req.ExpiresAt, req.CreatedAt,
		)
		return err
	})
}

// GetApprovalRequest retrieves an approval request by ID.
func GetApprovalRequest(ctx context.Context, pool *pgxpool.Pool, userID, orgID, id string) (*ApprovalRequest, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}

	var ar ApprovalRequest
	err := tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT id, org_id, team_id, request_type, resource_type, resource_id,
			       requested_by, reason, status, decided_by, decision_reason,
			       decided_at, expires_at, created_at
			  FROM governance.approval_requests
			 WHERE id = $1`, id)

		return row.Scan(
			&ar.ID, &ar.OrgID, &ar.TeamID, &ar.RequestType, &ar.ResourceType, &ar.ResourceID,
			&ar.RequestedBy, &ar.Reason, &ar.Status, &ar.DecidedBy, &ar.DecisionReason,
			&ar.DecidedAt, &ar.ExpiresAt, &ar.CreatedAt,
		)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("governance: approval request %s not found", id)
		}
		return nil, fmt.Errorf("governance: get approval request: %w", err)
	}
	return &ar, nil
}

// ListApprovalRequests returns paged approval requests, optionally filtered by status.
func ListApprovalRequests(ctx context.Context, pool *pgxpool.Pool, userID, orgID, status string, limit, offset int) ([]ApprovalRequest, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	if limit <= 0 {
		limit = 50
	}

	var results []ApprovalRequest
	err := tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		var query string
		var args []interface{}

		if status != "" {
			query = `
				SELECT id, org_id, COALESCE(team_id::text, ''), request_type, resource_type, resource_id,
				       requested_by, reason, status, COALESCE(decided_by::text, ''), COALESCE(decision_reason, ''),
				       decided_at, expires_at, created_at
				  FROM governance.approval_requests
				 WHERE status = $1
				 ORDER BY created_at DESC
				 LIMIT $2 OFFSET $3`
			args = []interface{}{status, limit, offset}
		} else {
			query = `
				SELECT id, org_id, COALESCE(team_id::text, ''), request_type, resource_type, resource_id,
				       requested_by, reason, status, COALESCE(decided_by::text, ''), COALESCE(decision_reason, ''),
				       decided_at, expires_at, created_at
				  FROM governance.approval_requests
				 ORDER BY created_at DESC
				 LIMIT $1 OFFSET $2`
			args = []interface{}{limit, offset}
		}

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var ar ApprovalRequest
			if scanErr := rows.Scan(
				&ar.ID, &ar.OrgID, &ar.TeamID, &ar.RequestType, &ar.ResourceType, &ar.ResourceID,
				&ar.RequestedBy, &ar.Reason, &ar.Status, &ar.DecidedBy, &ar.DecisionReason,
				&ar.DecidedAt, &ar.ExpiresAt, &ar.CreatedAt,
			); scanErr != nil {
				return scanErr
			}
			results = append(results, ar)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("governance: list approval requests: %w", err)
	}
	return results, nil
}

// LegacyDecideApproval is the Phase-4 entrypoint that flips the
// approval_requests row to 'approved' or 'rejected' atomically without
// recording per-approver decisions. New code should use DecideApproval
// (decisions.go) which records per-approver rows and supports two-person
// rule. Kept for back-compat with the existing controlplane handler that
// has not yet been migrated.
func LegacyDecideApproval(ctx context.Context, pool *pgxpool.Pool, userID, orgID, id, decision, reason string) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	if decision != "approved" && decision != "rejected" {
		return fmt.Errorf("governance: invalid decision %q; must be 'approved' or 'rejected'", decision)
	}

	return tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		// Fetch current state.
		var currentStatus, requestedBy string
		row := tx.QueryRow(ctx, `
			SELECT status, requested_by
			  FROM governance.approval_requests
			 WHERE id = $1`, id)
		if err := row.Scan(&currentStatus, &requestedBy); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("governance: approval request %s not found", id)
			}
			return err
		}

		if currentStatus != "pending" {
			return fmt.Errorf("governance: approval request %s is not pending (status=%s)", id, currentStatus)
		}

		if requestedBy == userID {
			return errors.New("governance: self-approval is forbidden")
		}

		now := time.Now()
		_, err := tx.Exec(ctx, `
			UPDATE governance.approval_requests
			   SET status = $1,
			       decided_by = $2,
			       decided_at = $3,
			       decision_reason = $4
			 WHERE id = $5`,
			decision, userID, now, reason, id,
		)
		return err
	})
}

// ExpirePendingApprovals marks expired pending approvals as 'expired'.
// This operates across all orgs (no RLS) and is intended for the retention worker.
func ExpirePendingApprovals(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	if pool == nil {
		return 0, errors.New("governance: pool is nil")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	tag, err := conn.Exec(ctx, `
		UPDATE governance.approval_requests
		   SET status = 'expired'
		 WHERE status = 'pending'
		   AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("governance: expire pending approvals: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
