package governance

// sla_deadline.go — pure-Go SLA deadline computation.
//
// Given a policy + finding creation time + severity, returns the
// deadline_at and warn_at timestamps to persist in
// governance.sla_deadlines. No DB, no pool.

import (
	"errors"
	"fmt"
	"time"
)

// SLAStatus is the derived runtime status of a finding with respect
// to its deadline. Derived, not stored.
type SLAStatus string

const (
	SLAOnTrack  SLAStatus = "on_track"
	SLADueSoon  SLAStatus = "due_soon"
	SLAOverdue  SLAStatus = "overdue"
	SLAResolved SLAStatus = "resolved"
)

// SLAPolicy mirrors governance.sla_policies row fields relevant to
// deadline math. Populated by the caller from the DB.
type SLAPolicy struct {
	ID                  string
	Severity            string // "critical" | "high" | "medium" | "low" | "info"
	RemediationDays     int
	WarnDaysBefore      int
	EscalateAfterHours  *int // nil = no auto-escalation
}

// ErrInvalidPolicy is returned when the policy's days/windows don't
// make sense together. Callers should refuse to persist such a
// policy; CHECK constraints in the migration catch the common cases
// at write time.
var ErrInvalidPolicy = errors.New("governance: invalid SLA policy")

// ComputeDeadlines returns (deadline_at, warn_at) for a finding
// created at `createdAt` under `policy`. deadline_at is
// createdAt + remediation_days; warn_at = deadline_at -
// warn_days_before. If warn_days_before >= remediation_days the
// warn_at collapses to createdAt (you're already in the warning
// window) — the policy probably wants fixing, but we don't panic.
func ComputeDeadlines(createdAt time.Time, policy SLAPolicy) (deadline, warn time.Time, err error) {
	if policy.RemediationDays <= 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: remediation_days=%d", ErrInvalidPolicy, policy.RemediationDays)
	}
	if policy.WarnDaysBefore < 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: warn_days_before=%d", ErrInvalidPolicy, policy.WarnDaysBefore)
	}
	deadline = createdAt.Add(time.Duration(policy.RemediationDays) * 24 * time.Hour)
	warnDelta := time.Duration(policy.WarnDaysBefore) * 24 * time.Hour
	warn = deadline.Add(-warnDelta)
	if warn.Before(createdAt) {
		warn = createdAt
	}
	return deadline, warn, nil
}

// DeriveStatus returns the runtime SLA status at `now`.
//
// Precedence:
//   1. resolved_at set           → resolved  (terminal)
//   2. breached_at set OR now >= deadline_at → overdue
//   3. now >= warn_at            → due_soon
//   4. else                       → on_track
func DeriveStatus(now, deadline, warn time.Time, resolvedAt, breachedAt *time.Time) SLAStatus {
	if resolvedAt != nil && !resolvedAt.IsZero() {
		return SLAResolved
	}
	if (breachedAt != nil && !breachedAt.IsZero()) || !now.Before(deadline) {
		return SLAOverdue
	}
	if !now.Before(warn) {
		return SLADueSoon
	}
	return SLAOnTrack
}

// ShouldEscalate reports whether a breached finding has crossed the
// auto-escalation threshold. Returns false if the policy has no
// auto-escalation configured or the breach is too recent.
func ShouldEscalate(now time.Time, policy SLAPolicy, breachedAt *time.Time, alreadyEscalatedAt *time.Time) bool {
	if policy.EscalateAfterHours == nil || *policy.EscalateAfterHours <= 0 {
		return false
	}
	if breachedAt == nil || breachedAt.IsZero() {
		return false
	}
	if alreadyEscalatedAt != nil && !alreadyEscalatedAt.IsZero() {
		return false
	}
	return now.Sub(*breachedAt) >= time.Duration(*policy.EscalateAfterHours)*time.Hour
}
