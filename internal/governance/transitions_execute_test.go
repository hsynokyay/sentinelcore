package governance_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/governance"
)

// TestExecuteApprovedTransition walks the full closure flow:
// create approval → two approvals → ExecuteApprovedTransition → finding flips.
// Skipped without a live DB.
func TestExecuteApprovedTransition(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgID, projID, cleanup := seedOrgAndProject(t, pool, "sensitive")
	defer cleanup()

	requester := seedUser(t, pool, orgID, "security_admin")
	a1 := seedUser(t, pool, orgID, "security_admin")
	a2 := seedUser(t, pool, orgID, "security_admin")
	findingID := seedFinding(t, pool, orgID, projID, "mitigated")

	req, err := governance.CreateApprovalRequest(ctx, pool, governance.CreateApprovalReq{
		OrgID:             orgID,
		RequestedBy:       requester,
		RequestType:       "risk_closure",
		ResourceType:      "finding",
		ResourceID:        findingID,
		Reason:            "patched",
		RequiredApprovals: 2,
		TargetTransition:  "resolved",
		ProjectID:         &projID,
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	if _, err := governance.DecideApproval(ctx, pool, req.ID, a1, "approve", "ok"); err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if _, err := governance.DecideApproval(ctx, pool, req.ID, a2, "approve", "ok"); err != nil {
		t.Fatalf("second decide: %v", err)
	}

	if err := governance.ExecuteApprovedTransition(ctx, pool, req.ID); err != nil {
		t.Fatalf("ExecuteApprovedTransition: %v", err)
	}

	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM findings.findings WHERE id = $1`, findingID).Scan(&status); err != nil {
		t.Fatalf("read finding status: %v", err)
	}
	if status != "resolved" {
		t.Errorf("expected finding status=resolved, got %s", status)
	}

	// Approval row should now be 'executed'.
	var approvalStatus string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM governance.approval_requests WHERE id = $1`, req.ID).Scan(&approvalStatus); err != nil {
		t.Fatalf("read approval status: %v", err)
	}
	if approvalStatus != "executed" {
		t.Errorf("expected approval status=executed, got %s", approvalStatus)
	}

	// Calling again is a no-op (idempotent).
	if err := governance.ExecuteApprovedTransition(ctx, pool, req.ID); err != nil {
		t.Errorf("second ExecuteApprovedTransition should be idempotent, got %v", err)
	}
}

// TestExecuteApprovedTransitionRejectsNonApproved confirms we don't execute
// transitions on rows that haven't reached approved status.
func TestExecuteApprovedTransitionRejectsNonApproved(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgID, projID, cleanup := seedOrgAndProject(t, pool, "standard")
	defer cleanup()

	requester := seedUser(t, pool, orgID, "security_admin")
	findingID := seedFinding(t, pool, orgID, projID, "mitigated")

	req, err := governance.CreateApprovalRequest(ctx, pool, governance.CreateApprovalReq{
		OrgID:             orgID,
		RequestedBy:       requester,
		RequestType:       "risk_closure",
		ResourceType:      "finding",
		ResourceID:        findingID,
		Reason:            "patched",
		RequiredApprovals: 2,
		TargetTransition:  "resolved",
		ProjectID:         &projID,
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	// Status is 'pending' — execute should refuse.
	err = governance.ExecuteApprovedTransition(ctx, pool, req.ID)
	if err == nil {
		t.Fatal("expected error executing pending approval, got nil")
	}
	// Wrong-id case → ErrApprovalNotFound.
	if err := governance.ExecuteApprovedTransition(ctx, pool, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, governance.ErrApprovalNotFound) {
		t.Errorf("expected ErrApprovalNotFound for unknown id, got %v", err)
	}
}
