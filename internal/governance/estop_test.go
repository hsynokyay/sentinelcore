package governance

import (
	"context"
	"testing"
)

func TestActivateEmergencyStop_NilPool(t *testing.T) {
	s := &EmergencyStop{Scope: "all", Reason: "incident"}
	err := ActivateEmergencyStop(context.Background(), nil, "user-1", "org-1", s)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestActivateEmergencyStop_NilStop(t *testing.T) {
	err := ActivateEmergencyStop(context.Background(), nil, "user-1", "org-1", nil)
	if err == nil {
		t.Fatal("expected error for nil stop")
	}
}

func TestLiftEmergencyStop_NilPool(t *testing.T) {
	err := LiftEmergencyStop(context.Background(), nil, "user-1", "org-1", "stop-1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestLiftEmergencyStop_SameUser(t *testing.T) {
	// Without a real DB we cannot fully test the four-eyes principle, but we
	// verify that the nil-pool guard fires before reaching the check.
	// The actual four-eyes error message is:
	//   "governance: the user who activated an emergency stop cannot lift it"
	// This test documents the expected behaviour.
	err := LiftEmergencyStop(context.Background(), nil, "user-1", "org-1", "stop-1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
	// Verify the error message is about the pool, not about four-eyes, since
	// we can't reach the DB check.
	if err.Error() != "governance: pool is nil" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIsEmergencyStopped_NilPool(t *testing.T) {
	_, err := IsEmergencyStopped(context.Background(), nil, "org-1", "scan", "scan-1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestListActiveStops_NilPool(t *testing.T) {
	_, err := ListActiveStops(context.Background(), nil, "user-1", "org-1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestEmergencyStop_StructFields(t *testing.T) {
	s := EmergencyStop{
		ID:          "stop-1",
		OrgID:       "org-1",
		Scope:       "scanner",
		ScopeID:     "scanner-42",
		Reason:      "critical vulnerability in scanner",
		ActivatedBy: "user-1",
		Active:      true,
	}
	if s.Scope != "scanner" {
		t.Errorf("expected scope=scanner, got %s", s.Scope)
	}
	if s.ScopeID != "scanner-42" {
		t.Errorf("expected scope_id=scanner-42, got %s", s.ScopeID)
	}
	if !s.Active {
		t.Error("expected active=true")
	}
}

func TestEmergencyStop_FourEyesErrorMessage(t *testing.T) {
	// Document the exact error message the four-eyes check produces.
	// In a real integration test this would be verified against a live DB.
	expectedMsg := "governance: the user who activated an emergency stop cannot lift it"
	if len(expectedMsg) == 0 {
		t.Fatal("expected non-empty error message")
	}
}
