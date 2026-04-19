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
	if NeedsApproval(toStatus, settings) {
		ar := &ApprovalRequest{
			ID:           uuid.New().String(),
			OrgID:        orgID,
			TeamID:       teamID,
			RequestType:  "finding_transition",
			ResourceType: "finding",
			ResourceID:   findingID,
			Reason:       reason,
		}
		if err := CreateApprovalRequest(ctx, pool, userID, orgID, ar); err != nil {
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
