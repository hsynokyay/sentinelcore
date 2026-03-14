package policy

// PermissionMatrix defines what each role can do.
// Phase 1 uses 4 simplified roles:
//
//	platform_admin → full access
//	security_admin → project/scan/finding management, no user admin
//	appsec_analyst → scan/finding access, limited management
//	auditor → read-only access to findings, scans, audit logs
var PermissionMatrix = map[string]map[string]bool{
	"platform_admin": {
		"users.create": true, "users.read": true, "users.update": true, "users.delete": true,
		"orgs.create": true, "orgs.read": true, "orgs.update": true,
		"teams.create": true, "teams.read": true, "teams.update": true,
		"projects.create": true, "projects.read": true, "projects.update": true, "projects.delete": true,
		"scans.create": true, "scans.read": true, "scans.cancel": true,
		"findings.read": true, "findings.triage": true,
		"targets.create": true, "targets.read": true, "targets.verify": true, "targets.approve": true,
		"audit.read": true,
		"updates.import": true, "updates.trust": true,
		"system.config": true,
	},
	"security_admin": {
		"projects.create": true, "projects.read": true, "projects.update": true,
		"scans.create": true, "scans.read": true, "scans.cancel": true,
		"findings.read": true, "findings.triage": true,
		"targets.create": true, "targets.read": true, "targets.verify": true,
		"audit.read": true,
	},
	"appsec_analyst": {
		"projects.read": true,
		"scans.create": true, "scans.read": true,
		"findings.read": true, "findings.triage": true,
		"targets.read": true,
	},
	"auditor": {
		"projects.read": true,
		"scans.read":    true,
		"findings.read": true,
		"audit.read":    true,
	},
}

// Evaluate checks if a role has a specific permission.
func Evaluate(role, permission string) bool {
	perms, exists := PermissionMatrix[role]
	if !exists {
		return false
	}
	return perms[permission]
}
