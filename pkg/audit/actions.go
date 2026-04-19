package audit

// Action is the typed form of the `action` column in audit.audit_log.
// Callers must use one of the exported constants — plain string literals
// at emit sites are caught by a static check in CI (see docs plan §3).
//
// The canonical catalogue lives in docs/audit-action-taxonomy.md. Adding
// a new code here without adding it to the catalogue (or vice versa)
// fails actions_test.TestActionTaxonomyDriftCheck.
type Action string

// Domain returns the leading segment of the action code (before the first
// dot). Used by the risk-events projector to detect risk-lifecycle events
// in O(1).
func (a Action) Domain() string {
	s := string(a)
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i]
		}
	}
	return s
}

// Result values for AuditEvent.Result. Typed to keep the taxonomy tight.
const (
	ResultSuccess string = "success"
	ResultFailure string = "failure"
	ResultDenied  string = "denied"
)

// ---- Authentication & identity ------------------------------------------

const (
	AuthLoginSucceeded       Action = "auth.login.succeeded"
	AuthLoginFailed          Action = "auth.login.failed"
	AuthLogout               Action = "auth.logout"
	AuthRefreshSucceeded     Action = "auth.refresh.succeeded"
	AuthRefreshFailed        Action = "auth.refresh.failed"
	AuthSSOLoginSucceeded    Action = "auth.sso.login.succeeded"
	AuthSSOLoginFailed       Action = "auth.sso.login.failed"
	AuthSSOLogout            Action = "auth.sso.logout"
	AuthPasswordChanged      Action = "auth.password.changed"
	AuthPasswordResetRequest Action = "auth.password.reset_requested"
	AuthBreakGlassActivated  Action = "auth.break_glass.activated"
)

// ---- RBAC & membership --------------------------------------------------

const (
	RBACRoleCreated           Action = "rbac.role.created"
	RBACRoleUpdated           Action = "rbac.role.updated"
	RBACRoleDeleted           Action = "rbac.role.deleted"
	RBACPermissionGranted     Action = "rbac.permission.granted"
	RBACPermissionRevoked     Action = "rbac.permission.revoked"
	UserCreated               Action = "user.created"
	UserUpdated               Action = "user.updated"
	UserDisabled              Action = "user.disabled"
	UserEnabled               Action = "user.enabled"
	UserTeamMembershipAdded   Action = "user.team_membership.added"
	UserTeamMembershipRemoved Action = "user.team_membership.removed"
)

// ---- API keys -----------------------------------------------------------

const (
	APIKeyCreated      Action = "apikey.created"
	APIKeyRotated      Action = "apikey.rotated"
	APIKeyRevoked      Action = "apikey.revoked"
	APIKeyUsed         Action = "apikey.used" // sampled on the hot path
	APIKeyScopeChanged Action = "apikey.scope.changed"
)

// ---- Scans & findings ---------------------------------------------------

const (
	ScanTriggered          Action = "scan.triggered"
	ScanCancelled          Action = "scan.cancelled"
	ScanCompleted          Action = "scan.completed"
	ScanFailed             Action = "scan.failed"
	FindingCreated         Action = "finding.created"
	FindingStatusChanged   Action = "finding.status.changed"
	FindingAssigned        Action = "finding.assigned"
	FindingAnnotationAdded Action = "finding.annotation.added"
	FindingLegalHoldSet    Action = "finding.legal_hold.set"
	FindingLegalHoldClear  Action = "finding.legal_hold.cleared"
)

// ---- Risks (projected into audit.risk_events) ---------------------------

const (
	RiskCreated             Action = "risk.created"
	RiskSeenAgain           Action = "risk.seen_again"
	RiskScoreChanged        Action = "risk.score.changed"
	RiskStatusChanged       Action = "risk.status.changed"
	RiskRelationAdded       Action = "risk.relation.added"
	RiskRelationRemoved     Action = "risk.relation.removed"
	RiskEvidenceChanged     Action = "risk.evidence.changed"
	RiskResolved            Action = "risk.resolved"
	RiskReopened            Action = "risk.reopened"
	RiskMuted               Action = "risk.muted"
	RiskUnmuted             Action = "risk.unmuted"
	RiskAssigned            Action = "risk.assigned"
	RiskNoteAdded           Action = "risk.note.added"
	CorrelationRebuildTrigg Action = "correlation.rebuild.triggered"
)

// ---- Governance ---------------------------------------------------------

const (
	GovernanceApprovalRequested Action = "governance.approval.requested"
	GovernanceApprovalApproved  Action = "governance.approval.approved"
	GovernanceApprovalRejected  Action = "governance.approval.rejected"
	GovernanceApprovalExpired   Action = "governance.approval.expired"
	GovernanceEStopActivated    Action = "governance.emergency_stop.activated"
	GovernanceEStopLifted       Action = "governance.emergency_stop.lifted"
	GovernanceSLAViolated       Action = "governance.sla.violated"
	GovernanceSLAResolved       Action = "governance.sla.resolved"
)

// ---- SSO provider config ------------------------------------------------

const (
	SSOProviderCreated Action = "sso.provider.created"
	SSOProviderUpdated Action = "sso.provider.updated"
	SSOProviderDeleted Action = "sso.provider.deleted"
	SSOMappingUpserted Action = "sso.mapping.upserted"
	SSOMappingDeleted  Action = "sso.mapping.deleted"
)

// ---- Webhooks & notifications ------------------------------------------

const (
	WebhookConfigCreated      Action = "webhook.config.created"
	WebhookConfigUpdated      Action = "webhook.config.updated"
	WebhookConfigDeleted      Action = "webhook.config.deleted"
	WebhookDeliveryAttempted  Action = "webhook.delivery.attempted"
	WebhookDeliverySucceeded  Action = "webhook.delivery.succeeded"
	WebhookDeliveryFailed     Action = "webhook.delivery.failed"
	NotificationDispatched    Action = "notification.dispatched"
)

// ---- Configuration & system --------------------------------------------

const (
	ConfigSettingChanged        Action = "config.setting.changed"
	ConfigRetentionPolicyUpdate Action = "config.retention_policy.updated"
	ConfigScanQuotaChanged      Action = "config.scan_quota.changed"
	SystemWorkerStarted         Action = "system.worker.started"
	SystemWorkerStopped         Action = "system.worker.stopped"
	SystemMigrationApplied      Action = "system.migration.applied"
	SystemBackupSucceeded       Action = "system.backup.succeeded"
	SystemBackupFailed          Action = "system.backup.failed"
)

// ---- Meta (audit about audit) ------------------------------------------

const (
	AuditExportRequested     Action = "audit.export.requested"
	AuditExportDownloaded    Action = "audit.export.downloaded"
	AuditIntegrityPassed     Action = "audit.integrity.check.passed"
	AuditIntegrityFailed     Action = "audit.integrity.check.failed"
	AuditHMACKeyRotated      Action = "audit.hmac_key.rotated"
	AuditHMACKeyMissing      Action = "audit.hmac_key.missing"
	AuditGlobalAccessGranted Action = "audit.global_access.granted"
	AuditPartitionPurged     Action = "audit.partition.purged"
)

// AllActions returns a snapshot of every defined Action constant. Used by
// actions_test to diff against the taxonomy documentation.
func AllActions() []Action {
	return []Action{
		// auth
		AuthLoginSucceeded, AuthLoginFailed, AuthLogout,
		AuthRefreshSucceeded, AuthRefreshFailed,
		AuthSSOLoginSucceeded, AuthSSOLoginFailed, AuthSSOLogout,
		AuthPasswordChanged, AuthPasswordResetRequest, AuthBreakGlassActivated,
		// rbac + user
		RBACRoleCreated, RBACRoleUpdated, RBACRoleDeleted,
		RBACPermissionGranted, RBACPermissionRevoked,
		UserCreated, UserUpdated, UserDisabled, UserEnabled,
		UserTeamMembershipAdded, UserTeamMembershipRemoved,
		// apikey
		APIKeyCreated, APIKeyRotated, APIKeyRevoked, APIKeyUsed, APIKeyScopeChanged,
		// scan + finding
		ScanTriggered, ScanCancelled, ScanCompleted, ScanFailed,
		FindingCreated, FindingStatusChanged, FindingAssigned,
		FindingAnnotationAdded, FindingLegalHoldSet, FindingLegalHoldClear,
		// risk
		RiskCreated, RiskSeenAgain, RiskScoreChanged, RiskStatusChanged,
		RiskRelationAdded, RiskRelationRemoved, RiskEvidenceChanged,
		RiskResolved, RiskReopened, RiskMuted, RiskUnmuted,
		RiskAssigned, RiskNoteAdded, CorrelationRebuildTrigg,
		// governance
		GovernanceApprovalRequested, GovernanceApprovalApproved,
		GovernanceApprovalRejected, GovernanceApprovalExpired,
		GovernanceEStopActivated, GovernanceEStopLifted,
		GovernanceSLAViolated, GovernanceSLAResolved,
		// sso
		SSOProviderCreated, SSOProviderUpdated, SSOProviderDeleted,
		SSOMappingUpserted, SSOMappingDeleted,
		// webhook + notification
		WebhookConfigCreated, WebhookConfigUpdated, WebhookConfigDeleted,
		WebhookDeliveryAttempted, WebhookDeliverySucceeded, WebhookDeliveryFailed,
		NotificationDispatched,
		// config + system
		ConfigSettingChanged, ConfigRetentionPolicyUpdate, ConfigScanQuotaChanged,
		SystemWorkerStarted, SystemWorkerStopped, SystemMigrationApplied,
		SystemBackupSucceeded, SystemBackupFailed,
		// audit meta
		AuditExportRequested, AuditExportDownloaded,
		AuditIntegrityPassed, AuditIntegrityFailed,
		AuditHMACKeyRotated, AuditHMACKeyMissing,
		AuditGlobalAccessGranted, AuditPartitionPurged,
	}
}
