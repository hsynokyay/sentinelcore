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

// TriageFinding attempts a status transition for a finding.
// If the transition requires approval, it creates an ApprovalRequest and returns
// a result indicating approval is required. Otherwise it executes the transition
// directly and records an audit entry.
func TriageFinding(
	ctx context.Context,
	pool *pgxpool.Pool,
	userID, orgID string,
	findingID, fromStatus, toStatus, teamID, reason string,
	settings *OrgSettings,
) (*TriageResult, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	if settings == nil {
		return nil, errors.New("governance: settings is nil")
	}

	// Step 1: validate transition.
	if err := ValidateTransition(fromStatus, toStatus); err != nil {
		return nil, fmt.Errorf("governance: triage: %w", err)
	}

	// Step 2: check if approval is required.
	if NeedsApprovalForSettings(toStatus, settings) {
		ar := &ApprovalRequest{
			ID:           uuid.New().String(),
			OrgID:        orgID,
			TeamID:       teamID,
			RequestType:  "finding_transition",
			ResourceType: "finding",
			ResourceID:   findingID,
			Reason:       reason,
		}
		if err := LegacyCreateApprovalRequest(ctx, pool, userID, orgID, ar); err != nil {
			return nil, fmt.Errorf("governance: triage: create approval: %w", err)
		}
		return &TriageResult{
			ApprovalRequired: true,
			ApprovalID:       ar.ID,
		}, nil
	}

	// Step 3: execute transition directly.
	now := time.Now()
	err := tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		_, updateErr := tx.Exec(ctx, `
			UPDATE findings.findings
			   SET status = $1, updated_at = $2
			 WHERE id = $3 AND org_id = $4 AND status = $5`,
			toStatus, now, findingID, orgID, fromStatus,
		)
		if updateErr != nil {
			return updateErr
		}

		// Record transition in audit log.
		_, insertErr := tx.Exec(ctx, `
			INSERT INTO governance.finding_transitions (
				id, finding_id, org_id, team_id,
				from_status, to_status, changed_by, reason, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			uuid.New().String(), findingID, orgID, teamID,
			fromStatus, toStatus, userID, reason, now,
		)
		return insertErr
	})
	if err != nil {
		return nil, fmt.Errorf("governance: triage: execute transition: %w", err)
	}

	return &TriageResult{Transitioned: true}, nil
}

// ExecuteApprovedTransition applies the gated state transition recorded on
// an approved governance.approval_requests row. It is idempotent: a row is
// only executed once, after which its status flips to 'executed'. Calling
// the function on a non-approved row returns an error.
//
// Currently supports request_type='finding_transition' and
// request_type='risk_closure' targeting findings.findings.status. Other
// request types are a no-op-with-error so callers don't silently lose
// transitions.
func ExecuteApprovedTransition(ctx context.Context, pool *pgxpool.Pool, approvalReqID string) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	parsed, err := uuid.Parse(approvalReqID)
	if err != nil {
		return fmt.Errorf("governance: invalid approval request id %q: %w", approvalReqID, err)
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("governance: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		status           string
		resourceType     string
		resourceID       uuid.UUID
		targetTransition *string
		orgID            uuid.UUID
		decidedBy        *uuid.UUID
	)
	err = tx.QueryRow(ctx, `
		SELECT status, resource_type, resource_id, target_transition, org_id, decided_by
		  FROM governance.approval_requests
		 WHERE id = $1
		 FOR UPDATE
	`, parsed).Scan(&status, &resourceType, &resourceID, &targetTransition, &orgID, &decidedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrApprovalNotFound
		}
		return fmt.Errorf("governance: load approval request: %w", err)
	}

	// Idempotency: already executed is a successful no-op.
	if status == "executed" {
		return tx.Commit(ctx)
	}
	if status != "approved" {
		return fmt.Errorf("governance: approval %s not approved (status=%s)", approvalReqID, status)
	}
	if resourceType != "finding" {
		return fmt.Errorf("governance: unsupported resource_type %q for auto execution", resourceType)
	}
	if targetTransition == nil || *targetTransition == "" {
		return errors.New("governance: approval has no target_transition; nothing to execute")
	}

	now := time.Now()
	tag, err := tx.Exec(ctx, `
		UPDATE findings.findings
		   SET status = $1, updated_at = $2
		 WHERE id = $3 AND org_id = $4
	`, *targetTransition, now, resourceID, orgID)
	if err != nil {
		return fmt.Errorf("governance: execute finding transition: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("governance: finding %s not found in org %s", resourceID, orgID)
	}

	// Mark the approval row as executed so re-runs are idempotent.
	if _, err := tx.Exec(ctx, `
		UPDATE governance.approval_requests
		   SET status = 'executed'
		 WHERE id = $1 AND status = 'approved'
	`, parsed); err != nil {
		return fmt.Errorf("governance: mark approval executed: %w", err)
	}

	// Audit row in findings.finding_state_transitions so the closure shows up
	// in the same audit timeline as direct triage actions.
	if decidedBy != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO findings.finding_state_transitions (
				id, finding_id, from_status, to_status,
				reason, changed_by, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7)
		`,
			uuid.New(), resourceID,
			"approved", *targetTransition,
			"governance.approval.executed",
			*decidedBy,
			now,
		); err != nil {
			return fmt.Errorf("governance: insert transition audit: %w", err)
		}
	}

	return tx.Commit(ctx)
}
