package governance

// approval_fsm.go — pure state machine for the approval workflow.
// No DB, no pool, no HTTP. Unit-testable in isolation; the API layer
// calls Transition + persists the returned (state, counters).
//
// States:
//
//   pending   — initial, no decisions yet
//   reviewed  — required_approvers >= 2 AND one (different-from-
//               requester) approver has voted "approve"
//   approved  — quorum reached: approvals_received >= required_approvers
//               AND rejections_received = 0
//   rejected  — any reject vote at any time collapses here
//   expired   — auto by sweep at expires_at (terminal)
//
// The FSM is advisory — it computes the NEXT state given (current
// state, required, counters, decision, requester_id, approver_id).
// It never reads or writes; callers are responsible for the tx.

import "errors"

// ApprovalState is the set of allowed status values matching the
// approval_status_check CHECK constraint on governance.approval_requests.
type ApprovalState string

const (
	StatePending  ApprovalState = "pending"
	StateReviewed ApprovalState = "reviewed"
	StateApproved ApprovalState = "approved"
	StateRejected ApprovalState = "rejected"
	StateExpired  ApprovalState = "expired"
)

// ApprovalDecision is what an approver casts. Does not include
// "expire" — that transition happens to a state, not by a user.
type ApprovalDecision string

const (
	DecisionApprove ApprovalDecision = "approve"
	DecisionReject  ApprovalDecision = "reject"
)

// ApprovalRequestFSM is the FSM input. All fields are the values
// CURRENTLY persisted before the new decision is applied.
type ApprovalRequestFSM struct {
	State               ApprovalState
	RequiredApprovers   int
	ApprovalsReceived   int
	RejectionsReceived  int
	RequesterUserID     string
	// ApproverUserIDs is the set of users who've already voted.
	// Used to reject a second vote from the same user. Not needed
	// when the DB's PK on (request_id, approver_id) enforces it
	// — kept here so the FSM can be tested without a DB.
	ApproverUserIDs     []string
}

// ApprovalTransition is the FSM output: the NEW state plus the
// updated counters. The caller writes these back + inserts the
// approval_approvers row atomically.
type ApprovalTransition struct {
	NextState           ApprovalState
	ApprovalsReceived   int
	RejectionsReceived  int
}

// Sentinel errors — callers check with errors.Is for 4xx mapping.
var (
	ErrTerminalState      = errors.New("governance: request is in a terminal state")
	ErrRequesterCannotVote = errors.New("governance: requester cannot approve or reject their own request")
	ErrDuplicateVote      = errors.New("governance: approver has already voted on this request")
	ErrInvalidTransition  = errors.New("governance: transition not allowed from current state")
	ErrInvalidDecision    = errors.New("governance: decision must be approve or reject")
)

// Transition computes the post-decision state.
//
// Invariants enforced:
//   1. Decision must be approve | reject.
//   2. Requester ≠ approver.
//   3. Approver has not voted before.
//   4. Current state is pending or reviewed (other states are terminal).
//   5. RequiredApprovers >= 1.
//   6. A single reject collapses to rejected regardless of prior approvals.
//   7. Quorum: approvals_received+1 >= required AND rejections_received = 0 ⇒ approved.
//   8. Otherwise (approve in pending with required >= 2) ⇒ reviewed.
//
// The caller is responsible for the PERSIST step; this function
// does not know about the DB. Counters returned are the NEW values
// to persist.
func Transition(cur ApprovalRequestFSM, approverID string, d ApprovalDecision) (ApprovalTransition, error) {
	if d != DecisionApprove && d != DecisionReject {
		return ApprovalTransition{}, ErrInvalidDecision
	}
	if cur.RequiredApprovers < 1 {
		cur.RequiredApprovers = 1
	}

	// Terminal states refuse new decisions.
	switch cur.State {
	case StateApproved, StateRejected, StateExpired:
		return ApprovalTransition{}, ErrTerminalState
	case StatePending, StateReviewed:
		// proceed
	default:
		return ApprovalTransition{}, ErrInvalidTransition
	}

	if approverID == "" || approverID == cur.RequesterUserID {
		return ApprovalTransition{}, ErrRequesterCannotVote
	}
	for _, u := range cur.ApproverUserIDs {
		if u == approverID {
			return ApprovalTransition{}, ErrDuplicateVote
		}
	}

	// Apply the decision.
	next := ApprovalTransition{
		ApprovalsReceived:  cur.ApprovalsReceived,
		RejectionsReceived: cur.RejectionsReceived,
	}
	if d == DecisionApprove {
		next.ApprovalsReceived++
	} else {
		next.RejectionsReceived++
	}

	// A reject at any time is terminal.
	if next.RejectionsReceived > 0 {
		next.NextState = StateRejected
		return next, nil
	}

	// Quorum?
	if next.ApprovalsReceived >= cur.RequiredApprovers {
		next.NextState = StateApproved
		return next, nil
	}

	// Still need more approvals. In a 2+-approver policy the first
	// approve transitions pending → reviewed so the UI can show a
	// distinct "waiting for second signer" status. In a single-
	// approver policy we shouldn't hit this branch (quorum above).
	if cur.RequiredApprovers >= 2 {
		next.NextState = StateReviewed
		return next, nil
	}

	// Defensive default: stay pending. This is unreachable with
	// required=1 because quorum triggers above; kept for clarity.
	next.NextState = StatePending
	return next, nil
}

// IsTerminal reports whether a state accepts no further decisions.
func IsTerminal(s ApprovalState) bool {
	switch s {
	case StateApproved, StateRejected, StateExpired:
		return true
	}
	return false
}
