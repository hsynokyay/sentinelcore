package auth

import (
	"context"
	"testing"
)

func TestPrincipalContext_RoundTrip(t *testing.T) {
	p := Principal{
		Kind:   "user",
		OrgID:  "org-123",
		UserID: "user-456",
		Role:   "admin",
	}
	ctx := WithPrincipal(context.Background(), p)

	got, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("expected principal in context")
	}
	if got.UserID != "user-456" {
		t.Fatalf("want user-456, got %s", got.UserID)
	}
}

func TestPrincipalFromContext_Empty(t *testing.T) {
	_, ok := PrincipalFromContext(context.Background())
	if ok {
		t.Fatal("expected no principal")
	}
}

type fakeChecker map[string]map[string]struct{}

func (f fakeChecker) Can(role, perm string) bool {
	p, ok := f[role]
	if !ok {
		return false
	}
	_, ok = p[perm]
	return ok
}

func TestPrincipal_Can_User(t *testing.T) {
	checker := fakeChecker{"admin": {"scans.run": {}}}

	p := Principal{Kind: "user", Role: "admin"}
	if !p.Can("scans.run", checker) {
		t.Fatal("admin should have scans.run via checker")
	}
	if p.Can("users.manage", checker) {
		t.Fatal("admin should NOT have users.manage")
	}
}

func TestPrincipal_Can_APIKey(t *testing.T) {
	p := Principal{Kind: "api_key", Scopes: []string{"risks.read", "scans.read"}}
	if !p.Can("risks.read", nil) {
		t.Fatal("key with risks.read scope should allow")
	}
	if p.Can("scans.run", nil) {
		t.Fatal("key without scans.run scope should deny")
	}
}

func TestPrincipal_Can_UnknownKind(t *testing.T) {
	p := Principal{Kind: "weird"}
	if p.Can("anything", fakeChecker{}) {
		t.Fatal("unknown kind must deny")
	}
}
