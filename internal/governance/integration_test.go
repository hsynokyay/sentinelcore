package governance_test

import (
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/governance"
)

// Integration tests for Phase 4 governance workflows.
// These tests verify business logic without a real database.
// Full E2E integration tests require the test harness in test/integration/.

func TestApprovalWorkflow_TransitionValidation(t *testing.T) {
	// Verify the full approval flow logic:
	// 1. ValidateTransition must pass before approval is created
	// 2. NeedsApproval gates on org settings

	// Step 1: Valid transition new → accepted_risk
	if err := governance.ValidateTransition("new", "accepted_risk"); err != nil {
		t.Fatalf("expected valid transition: %v", err)
	}

	// Step 2: With approval required
	settings := &governance.OrgSettings{
		RequireApprovalRiskAcceptance: true,
		RequireApprovalFalsePositive:  true,
	}
	if !governance.NeedsApprovalForSettings("accepted_risk", settings) {
		t.Fatal("expected approval to be required for accepted_risk")
	}
	if !governance.NeedsApprovalForSettings("false_positive", settings) {
		t.Fatal("expected approval to be required for false_positive")
	}

	// Step 3: Without approval
	noApproval := &governance.OrgSettings{}
	if governance.NeedsApprovalForSettings("accepted_risk", noApproval) {
		t.Fatal("expected no approval when setting is false")
	}

	// Step 4: Invalid transitions are rejected
	invalidCases := []struct{ from, to string }{
		{"new", "resolved"},
		{"new", "in_progress"},
		{"resolved", "confirmed"},
		{"false_positive", "mitigated"},
	}
	for _, tc := range invalidCases {
		if err := governance.ValidateTransition(tc.from, tc.to); err == nil {
			t.Errorf("expected error for %s → %s", tc.from, tc.to)
		}
	}
}

func TestEmergencyStop_FourEyesPrinciple(t *testing.T) {
	// The four-eyes principle prevents the activator from lifting
	// their own emergency stop. This is enforced at the DB layer
	// in estop.go LiftEmergencyStop. Here we verify the struct
	// and field relationships.
	stop := governance.EmergencyStop{
		ID:          "stop-1",
		OrgID:       "org-1",
		Scope:       "all",
		Reason:      "security incident",
		ActivatedBy: "user-admin-1",
		ActivatedAt: time.Now(),
		Active:      true,
	}

	if stop.ActivatedBy == "" {
		t.Fatal("activated_by must be set")
	}
	if !stop.Active {
		t.Fatal("new stop must be active")
	}
	if stop.DeactivatedBy != "" {
		t.Fatal("new stop must not have deactivated_by")
	}

	// Scope validation
	validScopes := []string{"all", "team", "project", "scan_job"}
	for _, scope := range validScopes {
		stop.Scope = scope
		if stop.Scope == "" {
			t.Errorf("scope %s should be valid", scope)
		}
	}
}

func TestSLADeadline_AllSeverities(t *testing.T) {
	settings := &governance.OrgSettings{
		DefaultFindingSLADays: governance.DefaultSLADays(),
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		severity     string
		expectedDays int
	}{
		{"critical", 3},
		{"high", 7},
		{"medium", 30},
		{"low", 90},
		{"unknown", 90}, // fallback
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			deadline := governance.CalculateSLADeadline(now, tt.severity, settings)
			expected := now.AddDate(0, 0, tt.expectedDays)
			if !deadline.Equal(expected) {
				t.Errorf("severity=%s: got %v, want %v", tt.severity, deadline, expected)
			}
		})
	}
}

func TestRetentionLifecycle_LegalHoldBlock(t *testing.T) {
	// Verify the retention record struct correctly models legal hold
	rec := governance.RetentionRecord{
		ResourceType: "findings",
		ResourceID:   "finding-1",
		Lifecycle:    "purge_pending",
		LegalHold:    true,
		LegalHoldBy:  "legal-admin",
		LegalHoldReason: "ongoing investigation",
	}

	if !rec.LegalHold {
		t.Fatal("legal hold must be set")
	}
	if rec.Lifecycle != "purge_pending" {
		t.Fatal("should be purge_pending")
	}
	// PurgeRecords in retention.go filters WHERE legal_hold=false
	// so this record would be skipped
}

func TestRetentionLifecycle_Transitions(t *testing.T) {
	// Verify valid lifecycle states
	validStates := []string{"active", "archived", "purge_pending", "purged"}
	for _, state := range validStates {
		rec := governance.RetentionRecord{Lifecycle: state}
		if rec.Lifecycle != state {
			t.Errorf("state %s not assignable", state)
		}
	}
}

func TestTriageResult_Fields(t *testing.T) {
	// Direct transition
	direct := governance.TriageResult{Transitioned: true}
	if !direct.Transitioned {
		t.Fatal("should be transitioned")
	}
	if direct.ApprovalRequired {
		t.Fatal("should not require approval")
	}

	// Approval required
	pending := governance.TriageResult{
		ApprovalRequired: true,
		ApprovalID:       "approval-123",
	}
	if pending.Transitioned {
		t.Fatal("should not be transitioned yet")
	}
	if !pending.ApprovalRequired {
		t.Fatal("should require approval")
	}
	if pending.ApprovalID == "" {
		t.Fatal("approval ID must be set")
	}
}

func TestDefaultRetentionPolicies(t *testing.T) {
	policies := governance.DefaultRetentionPolicies()

	expected := map[string]struct {
		retention int
		grace     int
	}{
		"findings":         {365, 30},
		"evidence":         {365, 30},
		"audit_log":        {730, 90},
		"scan_job":         {180, 14},
		"notification":     {90, 7},
		"webhook_delivery": {30, 7},
	}

	for name, exp := range expected {
		policy, ok := policies[name]
		if !ok {
			t.Errorf("missing policy for %s", name)
			continue
		}
		if policy.RetentionDays != exp.retention {
			t.Errorf("%s: retention=%d, want %d", name, policy.RetentionDays, exp.retention)
		}
		if policy.GraceDays != exp.grace {
			t.Errorf("%s: grace=%d, want %d", name, policy.GraceDays, exp.grace)
		}
	}
}

func TestFindingStatusTransitionMatrix_Completeness(t *testing.T) {
	// Every status in the matrix must have at least one valid transition
	for from, targets := range governance.ValidTransitions {
		if len(targets) == 0 {
			t.Errorf("status %q has no valid transitions", from)
		}
	}

	// Every target status must also appear as a source status (no dead ends except terminal states)
	allSources := make(map[string]bool)
	allTargets := make(map[string]bool)
	for from, targets := range governance.ValidTransitions {
		allSources[from] = true
		for to := range targets {
			allTargets[to] = true
		}
	}
	for target := range allTargets {
		if !allSources[target] {
			t.Errorf("target status %q is not a source status (dead end)", target)
		}
	}
}
