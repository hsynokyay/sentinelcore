// Package authz contains DAST-specific authorization: role grants
// independent of the global JWT role, plus middleware to gate endpoints.
package authz

// Role is a DAST role name. New roles must be added to the CHECK constraint
// in migrations/045_dast_user_roles.up.sql.
type Role string

const (
	RoleRecorder       Role = "dast.recorder"
	RoleReviewer       Role = "dast.recording_reviewer"
	RoleScanOperator   Role = "dast.scan_operator"
	RoleRecordingAdmin Role = "dast.recording_admin"
	RoleAuditViewer    Role = "dast.audit_viewer"
)

// AllRoles returns every defined role in declaration order.
func AllRoles() []Role {
	return []Role{
		RoleRecorder,
		RoleReviewer,
		RoleScanOperator,
		RoleRecordingAdmin,
		RoleAuditViewer,
	}
}
