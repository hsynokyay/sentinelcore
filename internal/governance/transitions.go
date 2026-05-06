package governance

import "fmt"

// ValidTransitions defines allowed finding status transitions.
var ValidTransitions = map[string]map[string]bool{
	"new":             {"confirmed": true, "false_positive": true, "accepted_risk": true},
	"confirmed":       {"in_progress": true, "false_positive": true, "accepted_risk": true},
	"in_progress":     {"mitigated": true, "false_positive": true, "accepted_risk": true},
	"mitigated":       {"resolved": true, "reopened": true},
	"resolved":        {"reopened": true},
	"reopened":        {"confirmed": true, "in_progress": true, "false_positive": true, "accepted_risk": true},
	"accepted_risk":   {"reopened": true},
	"false_positive":  {"reopened": true},
}

// ApprovalReq describes the approval workflow attached to a target status:
// what kind of request to create (Kind) and the minimum number of distinct
// approvers required to fulfill it (MinApprovers).
type ApprovalReq struct {
	Kind         string
	MinApprovers int
}

// ApprovalTargets maps a target finding status to the default approval
// workflow that is required to reach it. The map is the *base* policy;
// runtime layers (org_settings, project sensitivity) further refine
// MinApprovers via NeedsApproval below.
var ApprovalTargets = map[string]ApprovalReq{
	"accepted_risk":  {Kind: "risk_acceptance", MinApprovers: 1},
	"false_positive": {Kind: "false_positive_mark", MinApprovers: 1},
	"resolved":       {Kind: "risk_closure", MinApprovers: 1},
}

// ValidateTransition checks if a status transition is allowed.
func ValidateTransition(from, to string) error {
	allowed, exists := ValidTransitions[from]
	if !exists {
		return fmt.Errorf("unknown status: %s", from)
	}
	if !allowed[to] {
		return fmt.Errorf("invalid transition from %q to %q", from, to)
	}
	return nil
}

// NeedsApprovalForSettings is the legacy helper retained for in-process
// callers (Phase-4 triage). It only knows about org_settings booleans
// and does NOT consider project sensitivity. New code should call
// NeedsApproval (closure.go) which queries the database.
func NeedsApprovalForSettings(targetStatus string, settings *OrgSettings) bool {
	switch targetStatus {
	case "accepted_risk":
		return settings.RequireApprovalRiskAcceptance
	case "false_positive":
		return settings.RequireApprovalFalsePositive
	default:
		return false
	}
}
