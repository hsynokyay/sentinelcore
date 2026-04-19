package apikeys

import (
	"errors"
	"testing"
)

func TestValidateScopes(t *testing.T) {
	known := map[string]struct{}{
		"risks.read":  {},
		"scans.read":  {},
		"scans.run":   {},
		"findings.read": {},
	}
	creator := map[string]struct{}{
		"risks.read":  {},
		"scans.read":  {},
		"findings.read": {},
	}

	t.Run("RejectsUnknownScope", func(t *testing.T) {
		err := ValidateScopes([]string{"does.not.exist"}, creator, known)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var e *UnknownScopeError
		if !errors.As(err, &e) {
			t.Fatalf("expected *UnknownScopeError, got %T: %v", err, err)
		}
		if e.Scope != "does.not.exist" {
			t.Errorf("Scope = %q, want %q", e.Scope, "does.not.exist")
		}
	})

	t.Run("RejectsPrivilegeEscalation", func(t *testing.T) {
		// scans.run is in known but NOT in creator's permission set
		err := ValidateScopes([]string{"scans.run"}, creator, known)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var e *PrivilegeEscalationError
		if !errors.As(err, &e) {
			t.Fatalf("expected *PrivilegeEscalationError, got %T: %v", err, err)
		}
		if e.Scope != "scans.run" {
			t.Errorf("Scope = %q, want %q", e.Scope, "scans.run")
		}
	})

	t.Run("AllowsSubsetOfCreator", func(t *testing.T) {
		// risks.read and scans.read are both in known and in creator
		err := ValidateScopes([]string{"risks.read", "scans.read"}, creator, known)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("AllowsIdentical", func(t *testing.T) {
		// all creator permissions passed verbatim — no escalation, all known
		all := []string{"risks.read", "scans.read", "findings.read"}
		err := ValidateScopes(all, creator, known)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("RejectsEmptyScopes", func(t *testing.T) {
		err := ValidateScopes([]string{}, creator, known)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, EmptyScopesError) {
			t.Fatalf("expected EmptyScopesError, got %T: %v", err, err)
		}
	})

	t.Run("RejectsDuplicates", func(t *testing.T) {
		err := ValidateScopes([]string{"risks.read", "risks.read"}, creator, known)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var e *DuplicateScopeError
		if !errors.As(err, &e) {
			t.Fatalf("expected *DuplicateScopeError, got %T: %v", err, err)
		}
		if e.Scope != "risks.read" {
			t.Errorf("Scope = %q, want %q", e.Scope, "risks.read")
		}
	})
}
