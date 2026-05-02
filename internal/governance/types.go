package governance

import "time"

// OrgSettings holds per-org governance configuration.
type OrgSettings struct {
	OrgID                         string                    `json:"org_id"`
	RequireApprovalRiskAcceptance bool                      `json:"require_approval_for_risk_acceptance"`
	RequireApprovalFalsePositive  bool                      `json:"require_approval_for_false_positive"`
	RequireApprovalScopeExpansion bool                      `json:"require_approval_for_scope_expansion"` // stored but trigger deferred to Phase 5
	DefaultFindingSLADays         map[string]int            `json:"default_finding_sla_days"`
	RetentionPolicies             map[string]RetentionPolicy `json:"retention_policies"`
	UpdatedAt                     time.Time                 `json:"updated_at"`
	UpdatedBy                     string                    `json:"updated_by,omitempty"`
}

// RetentionPolicy defines retention and grace periods for a resource type.
type RetentionPolicy struct {
	RetentionDays int `json:"retention_days"`
	GraceDays     int `json:"grace_days"`
}

// DefaultRetentionPolicies returns the default retention policies.
func DefaultRetentionPolicies() map[string]RetentionPolicy {
	return map[string]RetentionPolicy{
		"findings":         {RetentionDays: 365, GraceDays: 30},
		"evidence":         {RetentionDays: 365, GraceDays: 30},
		"audit_log":        {RetentionDays: 730, GraceDays: 90},
		"scan_job":         {RetentionDays: 180, GraceDays: 14},
		"notification":     {RetentionDays: 90, GraceDays: 7},
		"webhook_delivery": {RetentionDays: 30, GraceDays: 7},
	}
}

// DefaultSLADays returns default SLA days per severity.
func DefaultSLADays() map[string]int {
	return map[string]int{"critical": 3, "high": 7, "medium": 30, "low": 90}
}

// NewDefaultOrgSettings returns OrgSettings with defaults for the given org.
func NewDefaultOrgSettings(orgID string) OrgSettings {
	return OrgSettings{
		OrgID:                 orgID,
		DefaultFindingSLADays: DefaultSLADays(),
		RetentionPolicies:     DefaultRetentionPolicies(),
		UpdatedAt:             time.Now(),
	}
}

// ApprovalRequest represents a pending governance approval.
type ApprovalRequest struct {
	ID             string     `json:"id"`
	OrgID          string     `json:"org_id"`
	TeamID         string     `json:"team_id,omitempty"`
	RequestType    string     `json:"request_type"`
	ResourceType   string     `json:"resource_type"`
	ResourceID     string     `json:"resource_id"`
	RequestedBy    string     `json:"requested_by"`
	Reason         string     `json:"reason"`
	Status         string     `json:"status"`
	DecidedBy      string     `json:"decided_by,omitempty"`
	DecisionReason string     `json:"decision_reason,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// FindingAssignment represents an ownership assignment for a finding.
type FindingAssignment struct {
	ID          string     `json:"id"`
	FindingID   string     `json:"finding_id"`
	OrgID       string     `json:"org_id"`
	TeamID      string     `json:"team_id,omitempty"`
	AssignedTo  string     `json:"assigned_to"`
	AssignedBy  string     `json:"assigned_by"`
	DueAt       *time.Time `json:"due_at,omitempty"`
	Status      string     `json:"status"`
	Note        string     `json:"note,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// SLAViolation records when a finding breaches its SLA deadline.
type SLAViolation struct {
	ID         string     `json:"id"`
	FindingID  string     `json:"finding_id"`
	OrgID      string     `json:"org_id"`
	Severity   string     `json:"severity"`
	SLADays    int        `json:"sla_days"`
	DeadlineAt time.Time  `json:"deadline_at"`
	ViolatedAt time.Time  `json:"violated_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Escalated  bool       `json:"escalated"`
}

// EmergencyStop represents a kill-switch activation.
type EmergencyStop struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"org_id"`
	Scope         string     `json:"scope"`
	ScopeID       string     `json:"scope_id,omitempty"`
	Reason        string     `json:"reason"`
	ActivatedBy   string     `json:"activated_by"`
	ActivatedAt   time.Time  `json:"activated_at"`
	DeactivatedBy string     `json:"deactivated_by,omitempty"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty"`
	Active        bool       `json:"active"`
}

// RetentionRecord tracks the lifecycle of a resource for retention purposes.
type RetentionRecord struct {
	ID              string     `json:"id"`
	OrgID           string     `json:"org_id"`
	ResourceType    string     `json:"resource_type"`
	ResourceID      string     `json:"resource_id"`
	Lifecycle       string     `json:"lifecycle"`
	RetentionDays   int        `json:"retention_days"`
	ExpiresAt       time.Time  `json:"expires_at"`
	ArchivedAt      *time.Time `json:"archived_at,omitempty"`
	PurgeAfter      *time.Time `json:"purge_after,omitempty"`
	PurgedAt        *time.Time `json:"purged_at,omitempty"`
	LegalHold       bool       `json:"legal_hold"`
	LegalHoldBy     string     `json:"legal_hold_by,omitempty"`
	LegalHoldReason string     `json:"legal_hold_reason,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// TriageResult describes the outcome of a triage attempt.
type TriageResult struct {
	Transitioned     bool   `json:"transitioned"`
	ApprovalRequired bool   `json:"approval_required"`
	ApprovalID       string `json:"approval_id,omitempty"`
}

// Notification represents an in-app notification.
type Notification struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	UserID       string    `json:"user_id"`
	Category     string    `json:"category"`
	Title        string    `json:"title"`
	Body         string    `json:"body,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
	Read         bool      `json:"read"`
	CreatedAt    time.Time `json:"created_at"`
}
