package audit

// DAST recording event types. The audit Writer accepts arbitrary action
// strings; these constants ensure consistent naming across components.
const (
	EventDASTRecordingCreated         = "dast.recording.created"
	EventDASTRecordingApproved        = "dast.recording.approved"
	EventDASTRecordingRejected        = "dast.recording.rejected"
	EventDASTRecordingRevoked         = "dast.recording.revoked"
	EventDASTRecordingAccessed        = "dast.recording.accessed"
	EventDASTRecordingUsed            = "dast.recording.used"
	EventDASTRecordingSoftDeleted     = "dast.recording.soft_deleted"
	EventDASTRecordingHardDeleted     = "dast.recording.hard_deleted"
	EventDASTRecordingExpired         = "dast.recording.expired"
	EventDASTRecordingACLViolation    = "dast.recording.acl_violation"
	EventDASTRecordingIntegrityFailed = "dast.recording.integrity_failed"
	EventDASTRoleGranted              = "dast.role.granted"
	EventDASTRoleRevoked              = "dast.role.revoked"
)
