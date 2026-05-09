package governance_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/governance"
)

// TestNeedsApprovalForClosure exercises the policy-aware NeedsApproval
// function that consults org_settings + project sensitivity. Skipped
// without a live DB.
func TestNeedsApprovalForClosure(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	orgID, projID, cleanup := seedOrgAndProject(t, pool, "standard")
	defer cleanup()

	// Default org_settings: require_closure_approval=false, require_two_person_closure=false.
	required, min, kind, err := governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "resolved")
	if err != nil {
		t.Fatalf("NeedsApproval (default): %v", err)
	}
	if required {
		t.Errorf("expected required=false when require_closure_approval=false, got true")
	}
	if min != 0 {
		t.Errorf("expected min=0, got %d", min)
	}
	if kind != "" {
		t.Errorf("expected kind=\"\", got %q", kind)
	}

	// Enable org-wide closure approval.
	setOrgSetting(t, pool, orgID, "require_closure_approval", true)
	required, min, kind, err = governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "resolved")
	if err != nil {
		t.Fatalf("NeedsApproval (closure on): %v", err)
	}
	if !required {
		t.Errorf("expected required=true after enabling closure approval")
	}
	if min != 1 {
		t.Errorf("expected min=1, got %d", min)
	}
	if kind != "risk_closure" {
		t.Errorf("expected kind=\"risk_closure\", got %q", kind)
	}

	// Mark project sensitive + enable two-person closure → min=2.
	setProjectSensitivity(t, pool, projID, "sensitive")
	setOrgSetting(t, pool, orgID, "require_two_person_closure", true)
	required, min, _, err = governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "resolved")
	if err != nil {
		t.Fatalf("NeedsApproval (two-person): %v", err)
	}
	if !required {
		t.Errorf("expected required=true with two-person + sensitive project")
	}
	if min != 2 {
		t.Errorf("expected min=2, got %d", min)
	}

	// accepted_risk always triggers approval (independent of closure flag).
	required, _, kind, err = governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "accepted_risk")
	if err != nil {
		t.Fatalf("NeedsApproval (accepted_risk): %v", err)
	}
	if !required {
		t.Errorf("expected required=true for accepted_risk transition")
	}
	if kind != "risk_acceptance" {
		t.Errorf("expected kind=\"risk_acceptance\", got %q", kind)
	}

	// Unrelated transition (e.g. confirmed → in_progress) → no approval.
	required, _, _, err = governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "in_progress")
	if err != nil {
		t.Fatalf("NeedsApproval (in_progress): %v", err)
	}
	if required {
		t.Errorf("expected required=false for non-closure transition")
	}

	// Unused to pacify linter when the package is built without the suite running.
	_ = uuid.Nil
}
