package governance_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/governance"
)

// TestDecideApprovalForbidsSelfApproval ensures that the requester
// cannot record an approve/reject decision on their own request.
// Skipped without a live DB.
func TestDecideApprovalForbidsSelfApproval(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgID, projID, cleanup := seedOrgAndProject(t, pool, "standard")
	defer cleanup()

	requester := seedUser(t, pool, orgID, "security_admin")

	req, err := governance.CreateApprovalRequest(ctx, pool, governance.CreateApprovalReq{
		OrgID:             orgID,
		RequestedBy:       requester,
		RequestType:       "risk_closure",
		ResourceType:      "finding",
		ResourceID:        seedFinding(t, pool, orgID, projID, "mitigated"),
		Reason:            "test",
		RequiredApprovals: 1,
		TargetTransition:  "resolved",
		ProjectID:         &projID,
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	_, err = governance.DecideApproval(ctx, pool, req.ID, requester, "approve", "self")
	if !errors.Is(err, governance.ErrSelfApprovalForbidden) {
		t.Fatalf("expected ErrSelfApprovalForbidden, got %v", err)
	}
}

// TestDecideApprovalTwoPersonFulfilled walks the happy path: two
// distinct approvers each record an approve decision and the request
// transitions pending → approved on the second one. A third decision
// from one of the approvers is rejected as a duplicate.
func TestDecideApprovalTwoPersonFulfilled(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgID, projID, cleanup := seedOrgAndProject(t, pool, "sensitive")
	defer cleanup()

	requester := seedUser(t, pool, orgID, "security_admin")
	approver1 := seedUser(t, pool, orgID, "security_admin")
	approver2 := seedUser(t, pool, orgID, "security_admin")

	req, err := governance.CreateApprovalRequest(ctx, pool, governance.CreateApprovalReq{
		OrgID:             orgID,
		RequestedBy:       requester,
		RequestType:       "risk_closure",
		ResourceType:      "finding",
		ResourceID:        seedFinding(t, pool, orgID, projID, "mitigated"),
		Reason:            "test",
		RequiredApprovals: 2,
		TargetTransition:  "resolved",
		ProjectID:         &projID,
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	// First approval — still pending.
	updated, err := governance.DecideApproval(ctx, pool, req.ID, approver1, "approve", "looks good")
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if updated.Status != "pending" {
		t.Errorf("expected status=pending, got %s", updated.Status)
	}
	if updated.CurrentApprovals != 1 {
		t.Errorf("expected current_approvals=1, got %d", updated.CurrentApprovals)
	}

	// Second approval — promotes to approved.
	updated, err = governance.DecideApproval(ctx, pool, req.ID, approver2, "approve", "confirmed")
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if updated.Status != "approved" {
		t.Errorf("expected status=approved, got %s", updated.Status)
	}
	if updated.CurrentApprovals != 2 {
		t.Errorf("expected current_approvals=2, got %d", updated.CurrentApprovals)
	}

	// Same approver decides again on the now-approved row.
	_, err = governance.DecideApproval(ctx, pool, req.ID, approver1, "approve", "again")
	// At this point status is 'approved' so ErrAlreadyDecided is also
	// acceptable, since the request is no longer pending. We accept either.
	if !errors.Is(err, governance.ErrDuplicateDecision) && !errors.Is(err, governance.ErrAlreadyDecided) {
		t.Fatalf("expected duplicate or already-decided error, got %v", err)
	}
}

// TestDecideApprovalRejectShortCircuits ensures a single reject moves
// the request to rejected and refuses any subsequent decisions.
func TestDecideApprovalRejectShortCircuits(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgID, projID, cleanup := seedOrgAndProject(t, pool, "standard")
	defer cleanup()

	requester := seedUser(t, pool, orgID, "security_admin")
	a1 := seedUser(t, pool, orgID, "security_admin")
	a2 := seedUser(t, pool, orgID, "security_admin")

	req, err := governance.CreateApprovalRequest(ctx, pool, governance.CreateApprovalReq{
		OrgID:             orgID,
		RequestedBy:       requester,
		RequestType:       "risk_closure",
		ResourceType:      "finding",
		ResourceID:        seedFinding(t, pool, orgID, projID, "mitigated"),
		Reason:            "test",
		RequiredApprovals: 2,
		TargetTransition:  "resolved",
		ProjectID:         &projID,
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	if _, err := governance.DecideApproval(ctx, pool, req.ID, a1, "reject", "nope"); err != nil {
		t.Fatalf("reject decide: %v", err)
	}

	_, err = governance.DecideApproval(ctx, pool, req.ID, a2, "approve", "still ok")
	if !errors.Is(err, governance.ErrAlreadyDecided) {
		t.Fatalf("expected ErrAlreadyDecided, got %v", err)
	}
}
