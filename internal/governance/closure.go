package governance

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NeedsApproval decides whether a finding status transition (from → to)
// requires governance approval, the minimum number of approvers needed,
// and the request "kind" to record on the approval row.
//
// The decision layers three signals:
//
//  1. The base ApprovalTargets map: only target statuses listed there can
//     ever require approval. (resolved, accepted_risk, false_positive.)
//  2. governance.org_settings.require_closure_approval gates the 'resolved'
//     target. If it is false, closure is auto-approved (returns false).
//  3. core.projects.sensitivity + governance.org_settings.require_two_person_closure:
//     if the project is 'sensitive' or 'regulated' AND the org has the
//     two-person flag enabled, MinApprovers is bumped to at least 2.
//
// On unknown transitions (no entry in ApprovalTargets) it returns
// (false, 0, "", nil) so callers can proceed with a direct execution.
func NeedsApproval(ctx context.Context, pool *pgxpool.Pool, orgID, projectID uuid.UUID, _from, to string) (bool, int, string, error) {
	if pool == nil {
		return false, 0, "", errors.New("governance: pool is nil")
	}

	base, ok := ApprovalTargets[to]
	if !ok {
		return false, 0, "", nil
	}

	var (
		requireClosure   bool
		requireTwoPerson bool
		sensitivity      string
	)
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(os.require_closure_approval, false),
		       COALESCE(os.require_two_person_closure, false),
		       COALESCE(p.sensitivity, 'standard')
		FROM core.projects p
		LEFT JOIN governance.org_settings os ON os.org_id = $1
		WHERE p.id = $2
	`, orgID, projectID).Scan(&requireClosure, &requireTwoPerson, &sensitivity)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, 0, "", fmt.Errorf("governance: project %s not found", projectID)
		}
		return false, 0, "", fmt.Errorf("governance: load approval policy inputs: %w", err)
	}

	// Closure is the only target gated by an org-wide opt-in flag.
	if to == "resolved" && !requireClosure {
		return false, 0, "", nil
	}

	min := base.MinApprovers
	if requireTwoPerson && (sensitivity == "sensitive" || sensitivity == "regulated") {
		if min < 2 {
			min = 2
		}
	}
	return true, min, base.Kind, nil
}
