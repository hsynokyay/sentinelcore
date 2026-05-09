package governance

import (
	"errors"
	"testing"
)

// Test fixtures — two distinct user IDs + a request.
const (
	userRequester = "00000000-0000-0000-0000-000000000001"
	userApprover1 = "00000000-0000-0000-0000-000000000002"
	userApprover2 = "00000000-0000-0000-0000-000000000003"
)

func TestTransition_SingleApprover_Approve(t *testing.T) {
	cur := ApprovalRequestFSM{
		State:             StatePending,
		RequiredApprovers: 1,
		RequesterUserID:   userRequester,
	}
	got, err := Transition(cur, userApprover1, DecisionApprove)
	if err != nil {
		t.Fatal(err)
	}
	if got.NextState != StateApproved {
		t.Errorf("want approved, got %q", got.NextState)
	}
	if got.ApprovalsReceived != 1 {
		t.Errorf("approvals=%d", got.ApprovalsReceived)
	}
}

func TestTransition_TwoPerson_OneThenTwo(t *testing.T) {
	cur := ApprovalRequestFSM{
		State:             StatePending,
		RequiredApprovers: 2,
		RequesterUserID:   userRequester,
	}
	// First approve → reviewed
	t1, err := Transition(cur, userApprover1, DecisionApprove)
	if err != nil || t1.NextState != StateReviewed {
		t.Fatalf("first approve: state=%q err=%v", t1.NextState, err)
	}

	// Second approve by DIFFERENT user → approved
	cur.State = t1.NextState
	cur.ApprovalsReceived = t1.ApprovalsReceived
	cur.RejectionsReceived = t1.RejectionsReceived
	cur.ApproverUserIDs = []string{userApprover1}

	t2, err := Transition(cur, userApprover2, DecisionApprove)
	if err != nil || t2.NextState != StateApproved {
		t.Fatalf("second approve: state=%q err=%v", t2.NextState, err)
	}
}

func TestTransition_RequesterCannotVote(t *testing.T) {
	cur := ApprovalRequestFSM{
		State:             StatePending,
		RequiredApprovers: 1,
		RequesterUserID:   userRequester,
	}
	_, err := Transition(cur, userRequester, DecisionApprove)
	if !errors.Is(err, ErrRequesterCannotVote) {
		t.Errorf("want ErrRequesterCannotVote, got %v", err)
	}
}

func TestTransition_DuplicateVote(t *testing.T) {
	cur := ApprovalRequestFSM{
		State:             StateReviewed,
		RequiredApprovers: 2,
		ApprovalsReceived: 1,
		RequesterUserID:   userRequester,
		ApproverUserIDs:   []string{userApprover1},
	}
	_, err := Transition(cur, userApprover1, DecisionApprove)
	if !errors.Is(err, ErrDuplicateVote) {
		t.Errorf("want ErrDuplicateVote, got %v", err)
	}
}

func TestTransition_RejectCollapses(t *testing.T) {
	// Even after 2 approvals, a reject collapses to rejected.
	cur := ApprovalRequestFSM{
		State:             StateReviewed,
		RequiredApprovers: 3,
		ApprovalsReceived: 2,
		RequesterUserID:   userRequester,
		ApproverUserIDs:   []string{userApprover1, userApprover2},
	}
	got, err := Transition(cur, "00000000-0000-0000-0000-000000000009", DecisionReject)
	if err != nil {
		t.Fatal(err)
	}
	if got.NextState != StateRejected {
		t.Errorf("want rejected, got %q", got.NextState)
	}
	if got.RejectionsReceived != 1 {
		t.Errorf("rejections=%d", got.RejectionsReceived)
	}
}

func TestTransition_TerminalRefusesNewDecision(t *testing.T) {
	for _, term := range []ApprovalState{StateApproved, StateRejected, StateExpired} {
		cur := ApprovalRequestFSM{State: term, RequiredApprovers: 1, RequesterUserID: userRequester}
		if _, err := Transition(cur, userApprover1, DecisionApprove); !errors.Is(err, ErrTerminalState) {
			t.Errorf("%s: want ErrTerminalState, got %v", term, err)
		}
	}
}

func TestTransition_InvalidDecision(t *testing.T) {
	cur := ApprovalRequestFSM{State: StatePending, RequiredApprovers: 1, RequesterUserID: userRequester}
	if _, err := Transition(cur, userApprover1, "maybe"); !errors.Is(err, ErrInvalidDecision) {
		t.Errorf("want ErrInvalidDecision, got %v", err)
	}
}

func TestIsTerminal(t *testing.T) {
	for _, c := range []struct {
		s    ApprovalState
		want bool
	}{
		{StatePending, false},
		{StateReviewed, false},
		{StateApproved, true},
		{StateRejected, true},
		{StateExpired, true},
	} {
		if got := IsTerminal(c.s); got != c.want {
			t.Errorf("IsTerminal(%s)=%v want %v", c.s, got, c.want)
		}
	}
}
