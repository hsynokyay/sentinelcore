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
		"findings.read": true, "findings.triage": true, "findings.legal_hold": true,
		"targets.create": true, "targets.read": true, "targets.verify": true, "targets.approve": true,
		"authprofiles.create": true, "authprofiles.read": true, "authprofiles.delete": true,
		"artifacts.create": true, "artifacts.read": true, "artifacts.delete": true,
		"audit.read": true,
		"updates.import": true, "updates.trust": true,
		"system.config": true,
		// Phase 4: governance
		"governance.settings.read": true, "governance.settings.write": true,
		"governance.approvals.read": true, "governance.approvals.decide": true,
		"governance.emergency_stop.activate": true, "governance.emergency_stop.lift": true,
		// Phase 5 governance-ops: SLA dashboard + per-project policies.
		"governance.sla.read": true, "governance.sla.write": true,
		"webhooks.read": true, "webhooks.manage": true,
		"retention.read": true, "retention.manage": true,
		"reports.read": true,
	},
	"security_admin": {
		"projects.create": true, "projects.read": true, "projects.update": true,
		"scans.create": true, "scans.read": true, "scans.cancel": true,
		"findings.read": true, "findings.triage": true, "findings.legal_hold": true,
		"targets.create": true, "targets.read": true, "targets.verify": true,
		"authprofiles.create": true, "authprofiles.read": true, "authprofiles.delete": true,
		"artifacts.create": true, "artifacts.read": true, "artifacts.delete": true,
		"audit.read": true,
		// Phase 4: governance
		"governance.settings.read": true, "governance.settings.write": true,
		"governance.approvals.read": true, "governance.approvals.decide": true,
		"governance.emergency_stop.activate": true,
		// Phase 5 governance-ops: SLA dashboard + per-project policies.
		"governance.sla.read": true, "governance.sla.write": true,
		"webhooks.read": true, "webhooks.manage": true,
		"retention.read": true,
		"reports.read": true,
	},
	"appsec_analyst": {
		"projects.read": true,
		"scans.create": true, "scans.read": true,
		"findings.read": true, "findings.triage": true,
		"targets.read": true,
		"authprofiles.read": true,
		"artifacts.read": true, "artifacts.create": true,
		// Phase 4: governance
		"governance.approvals.read": true,
		// Phase 5 governance-ops: analysts read but don't write SLA policies.
		"governance.sla.read": true,
		"webhooks.read": true,
		"reports.read": true,
	},
	"auditor": {
		"projects.read": true,
		"scans.read":    true,
		"findings.read": true,
		"audit.read":    true,
		// Phase 4: governance
		"governance.settings.read": true,
		"governance.approvals.read": true,
		// Phase 5 governance-ops: auditor reads SLA dashboard, no write.
		"governance.sla.read": true,
		"webhooks.read": true,
		"retention.read": true,
		"reports.read": true,
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
