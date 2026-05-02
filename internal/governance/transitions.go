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

// ApprovalTargets maps statuses that may require approval to their org setting key.
var ApprovalTargets = map[string]string{
	"accepted_risk":  "require_approval_for_risk_acceptance",
	"false_positive": "require_approval_for_false_positive",
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

// NeedsApproval checks if a transition to the given status needs org-level approval.
func NeedsApproval(targetStatus string, settings *OrgSettings) bool {
	switch targetStatus {
	case "accepted_risk":
		return settings.RequireApprovalRiskAcceptance
	case "false_positive":
		return settings.RequireApprovalFalsePositive
	default:
		return false
	}
}
