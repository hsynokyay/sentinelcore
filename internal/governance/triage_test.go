package governance

import (
	"context"
	"testing"
)

func TestTriageFinding_NilPool(t *testing.T) {
	s := NewDefaultOrgSettings("org-1")
	_, err := TriageFinding(context.Background(), nil, "user-1", "org-1", "f-1", "new", "confirmed", "", "reason", &s)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestTriageFinding_NilSettings(t *testing.T) {
	_, err := TriageFinding(context.Background(), nil, "user-1", "org-1", "f-1", "new", "confirmed", "", "reason", nil)
	if err == nil {
		t.Fatal("expected error for nil settings")
	}
}

func TestTriageFinding_InvalidTransition(t *testing.T) {
	s := NewDefaultOrgSettings("org-1")
	_, err := TriageFinding(context.Background(), nil, "user-1", "org-1", "f-1", "new", "resolved", "", "reason", &s)
	if err == nil {
		t.Fatal("expected error for invalid transition")
	}
}

func TestTriageFinding_ValidationOrder(t *testing.T) {
	// Even with nil pool, invalid transition should be caught first only when settings is provided.
	s := NewDefaultOrgSettings("org-1")
	// nil pool + valid transition → pool error
	_, err := TriageFinding(context.Background(), nil, "u", "o", "f", "new", "confirmed", "", "", &s)
	if err == nil {
		t.Fatal("expected error for nil pool with valid transition")
	}
	// nil pool + invalid transition → transition error (pool check comes first)
	_, err = TriageFinding(context.Background(), nil, "u", "o", "f", "new", "resolved", "", "", &s)
	if err == nil {
		t.Fatal("expected error for invalid transition")
	}
}

func TestTriageResult_Struct(t *testing.T) {
	r := TriageResult{Transitioned: true}
	if !r.Transitioned {
		t.Error("expected Transitioned=true")
	}
	if r.ApprovalRequired {
		t.Error("expected ApprovalRequired=false")
	}
	if r.ApprovalID != "" {
		t.Error("expected empty ApprovalID")
	}
}
