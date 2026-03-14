package policy

import "testing"

func TestEvaluate_PlatformAdmin_HasAllPermissions(t *testing.T) {
	perms := []string{"users.create", "orgs.create", "scans.create", "findings.read", "audit.read", "updates.import", "system.config"}
	for _, p := range perms {
		if !Evaluate("platform_admin", p) {
			t.Errorf("platform_admin should have %s", p)
		}
	}
}

func TestEvaluate_Auditor_CannotCreateScans(t *testing.T) {
	if Evaluate("auditor", "scans.create") {
		t.Error("auditor should NOT have scans.create")
	}
}

func TestEvaluate_Auditor_CanReadAudit(t *testing.T) {
	if !Evaluate("auditor", "audit.read") {
		t.Error("auditor should have audit.read")
	}
}

func TestEvaluate_UnknownRole_DeniesAll(t *testing.T) {
	if Evaluate("hacker", "users.create") {
		t.Error("unknown role should be denied")
	}
}

func TestEvaluate_SecurityAdmin_CannotManageUsers(t *testing.T) {
	if Evaluate("security_admin", "users.create") {
		t.Error("security_admin should NOT have users.create")
	}
}

func TestEvaluate_AppsecAnalyst_CanCreateScans(t *testing.T) {
	if !Evaluate("appsec_analyst", "scans.create") {
		t.Error("appsec_analyst should have scans.create")
	}
}
