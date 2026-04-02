package governance

import "testing"

func TestValidateTransition(t *testing.T) {
	tests := []struct {
		from, to string
		wantErr  bool
	}{
		{"new", "confirmed", false},
		{"new", "false_positive", false},
		{"new", "accepted_risk", false},
		{"new", "resolved", true},
		{"new", "in_progress", true},
		{"confirmed", "in_progress", false},
		{"in_progress", "mitigated", false},
		{"mitigated", "resolved", false},
		{"mitigated", "reopened", false},
		{"resolved", "reopened", false},
		{"resolved", "confirmed", true},
		{"accepted_risk", "reopened", false},
		{"false_positive", "reopened", false},
		{"false_positive", "confirmed", true},
		{"unknown", "new", true},
	}
	for _, tt := range tests {
		t.Run(tt.from+"->"+tt.to, func(t *testing.T) {
			err := ValidateTransition(tt.from, tt.to)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTransition(%q, %q) error = %v, wantErr %v", tt.from, tt.to, err, tt.wantErr)
			}
		})
	}
}

func TestNeedsApproval(t *testing.T) {
	noApproval := &OrgSettings{}
	withApproval := &OrgSettings{
		RequireApprovalRiskAcceptance: true,
		RequireApprovalFalsePositive:  true,
	}

	if NeedsApproval("accepted_risk", noApproval) {
		t.Error("expected no approval needed when setting is false")
	}
	if !NeedsApproval("accepted_risk", withApproval) {
		t.Error("expected approval needed when setting is true")
	}
	if NeedsApproval("confirmed", withApproval) {
		t.Error("confirmed should never need approval")
	}
	if !NeedsApproval("false_positive", withApproval) {
		t.Error("expected false_positive to need approval when setting is true")
	}
}

func TestDefaultOrgSettings(t *testing.T) {
	s := NewDefaultOrgSettings("org-1")
	if s.RequireApprovalRiskAcceptance {
		t.Error("default should be false")
	}
	if s.DefaultFindingSLADays["critical"] != 3 {
		t.Errorf("expected critical SLA=3, got %d", s.DefaultFindingSLADays["critical"])
	}
	if s.RetentionPolicies["findings"].RetentionDays != 365 {
		t.Error("expected findings retention 365 days")
	}
}
