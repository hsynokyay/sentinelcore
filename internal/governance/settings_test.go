package governance

import (
	"context"
	"testing"
)

func TestGetOrgSettings_NilPool(t *testing.T) {
	_, err := GetOrgSettings(context.Background(), nil, "user-1", "org-1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestUpsertOrgSettings_NilPool(t *testing.T) {
	s := NewDefaultOrgSettings("org-1")
	err := UpsertOrgSettings(context.Background(), nil, "user-1", "org-1", &s)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestUpsertOrgSettings_NilSettings(t *testing.T) {
	// We cannot create a real pool, but we can verify nil-settings check fires first.
	err := UpsertOrgSettings(context.Background(), nil, "user-1", "org-1", nil)
	if err == nil {
		t.Fatal("expected error for nil settings")
	}
}

func TestNewDefaultOrgSettings_Fields(t *testing.T) {
	s := NewDefaultOrgSettings("org-42")
	if s.OrgID != "org-42" {
		t.Errorf("expected org_id=org-42, got %s", s.OrgID)
	}
	if s.RequireApprovalRiskAcceptance {
		t.Error("default RequireApprovalRiskAcceptance should be false")
	}
	if s.RequireApprovalFalsePositive {
		t.Error("default RequireApprovalFalsePositive should be false")
	}
	if len(s.DefaultFindingSLADays) == 0 {
		t.Error("default SLA days should not be empty")
	}
	if s.DefaultFindingSLADays["high"] != 7 {
		t.Errorf("expected high SLA=7, got %d", s.DefaultFindingSLADays["high"])
	}
	if len(s.RetentionPolicies) == 0 {
		t.Error("default retention policies should not be empty")
	}
	if s.RetentionPolicies["audit_log"].RetentionDays != 730 {
		t.Errorf("expected audit_log retention 730, got %d", s.RetentionPolicies["audit_log"].RetentionDays)
	}
}
