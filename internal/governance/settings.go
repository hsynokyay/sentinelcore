package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

// GetOrgSettings retrieves the governance settings for an organisation.
// If no row exists, it returns NewDefaultOrgSettings(orgID).
func GetOrgSettings(ctx context.Context, pool *pgxpool.Pool, userID, orgID string) (*OrgSettings, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}

	var settings OrgSettings
	var slaJSON, retJSON []byte

	err := tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT org_id,
			       require_approval_for_risk_acceptance,
			       require_approval_for_false_positive,
			       require_approval_for_scope_expansion,
			       default_finding_sla_days,
			       retention_policies,
			       updated_at,
			       updated_by
			  FROM governance.org_settings
			 WHERE org_id = $1`, orgID)

		return row.Scan(
			&settings.OrgID,
			&settings.RequireApprovalRiskAcceptance,
			&settings.RequireApprovalFalsePositive,
			&settings.RequireApprovalScopeExpansion,
			&slaJSON,
			&retJSON,
			&settings.UpdatedAt,
			&settings.UpdatedBy,
		)
	})

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			defaults := NewDefaultOrgSettings(orgID)
			return &defaults, nil
		}
		return nil, fmt.Errorf("governance: get org settings: %w", err)
	}

	if err := json.Unmarshal(slaJSON, &settings.DefaultFindingSLADays); err != nil {
		return nil, fmt.Errorf("governance: unmarshal sla_days: %w", err)
	}
	if err := json.Unmarshal(retJSON, &settings.RetentionPolicies); err != nil {
		return nil, fmt.Errorf("governance: unmarshal retention_policies: %w", err)
	}

	return &settings, nil
}

// UpsertOrgSettings inserts or updates governance settings for an organisation.
func UpsertOrgSettings(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, settings *OrgSettings) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	if settings == nil {
		return errors.New("governance: settings is nil")
	}

	slaJSON, err := json.Marshal(settings.DefaultFindingSLADays)
	if err != nil {
		return fmt.Errorf("governance: marshal sla_days: %w", err)
	}
	retJSON, err := json.Marshal(settings.RetentionPolicies)
	if err != nil {
		return fmt.Errorf("governance: marshal retention_policies: %w", err)
	}

	settings.UpdatedAt = time.Now()
	settings.UpdatedBy = userID
	settings.OrgID = orgID

	return tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO governance.org_settings (
				org_id,
				require_approval_for_risk_acceptance,
				require_approval_for_false_positive,
				require_approval_for_scope_expansion,
				default_finding_sla_days,
				retention_policies,
				updated_at,
				updated_by
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (org_id) DO UPDATE SET
				require_approval_for_risk_acceptance = EXCLUDED.require_approval_for_risk_acceptance,
				require_approval_for_false_positive  = EXCLUDED.require_approval_for_false_positive,
				require_approval_for_scope_expansion = EXCLUDED.require_approval_for_scope_expansion,
				default_finding_sla_days             = EXCLUDED.default_finding_sla_days,
				retention_policies                   = EXCLUDED.retention_policies,
				updated_at                           = EXCLUDED.updated_at,
				updated_by                           = EXCLUDED.updated_by`,
			settings.OrgID,
			settings.RequireApprovalRiskAcceptance,
			settings.RequireApprovalFalsePositive,
			settings.RequireApprovalScopeExpansion,
			slaJSON,
			retJSON,
			settings.UpdatedAt,
			settings.UpdatedBy,
		)
		return execErr
	})
}
