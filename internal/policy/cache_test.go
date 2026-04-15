package policy

import (
	"context"
	"testing"
)

func TestCache_CanFalseBeforeLoad(t *testing.T) {
	c := NewCache()
	if c.Can("owner", "risks.read") {
		t.Fatal("expected false before Reload")
	}
}

func TestCache_ReloadMatchesDB(t *testing.T) {
	pool := testPool(t)
	c := NewCache()
	if err := c.Reload(context.Background(), pool); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !c.Can("owner", "users.manage") {
		t.Fatal("owner should have users.manage")
	}
	if c.Can("admin", "users.manage") {
		t.Fatal("admin must NOT have users.manage")
	}
	if !c.Can("developer", "risks.read") {
		t.Fatal("developer should have risks.read")
	}
	if c.Can("developer", "scans.run") {
		t.Fatal("developer must NOT have scans.run")
	}
	if !c.HasPermission("scans.run") {
		t.Fatal("HasPermission should return true for known permission")
	}
	if c.HasPermission("nonexistent.perm") {
		t.Fatal("HasPermission should return false for unknown")
	}
}
