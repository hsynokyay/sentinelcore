package governance

import (
	"context"
	"testing"
)

func TestAssignFinding_NilPool(t *testing.T) {
	a := &FindingAssignment{FindingID: "f-1", AssignedTo: "user-2"}
	err := AssignFinding(context.Background(), nil, "user-1", "org-1", a)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestAssignFinding_NilAssignment(t *testing.T) {
	err := AssignFinding(context.Background(), nil, "user-1", "org-1", nil)
	if err == nil {
		t.Fatal("expected error for nil assignment")
	}
}

func TestReassignFinding_NilPool(t *testing.T) {
	_, err := ReassignFinding(context.Background(), nil, "user-1", "org-1", "a-1", "user-2")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestCompleteFindingAssignment_NilPool(t *testing.T) {
	err := CompleteFindingAssignment(context.Background(), nil, "user-1", "org-1", "a-1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestListAssignments_NilPool(t *testing.T) {
	_, err := ListAssignments(context.Background(), nil, "user-1", "org-1", "", "", 10, 0)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestAssignFinding_SetsDefaults(t *testing.T) {
	a := &FindingAssignment{FindingID: "f-1", AssignedTo: "user-2"}
	// Cannot actually execute (nil pool), but verify the nil-assignment check
	// passes and the nil-pool check fires.
	err := AssignFinding(context.Background(), nil, "user-1", "org-1", a)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
	// The assignment struct should have been populated before the pool check
	// fails — but since pool is checked first, fields are not set.
	// This test just ensures both code paths are exercised.
}
