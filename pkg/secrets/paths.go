package secrets

// Canonical secret paths. Every caller fetches by one of these constants
// — typos in ad-hoc path strings are a class of bug the Go compiler
// can't catch without the constant indirection.
//
// The taxonomy mirrors docs/superpowers/plans/2026-04-18-phase7-data-security.md §3.2.
// A drift-check test (paths_test.go) diffs this list against the doc at
// CI so adding a path here requires updating the documentation.

// Tier 0 — Root secrets.
const (
	PathAESMaster    = "tier0/aes/master"     // AES-256, 32 bytes
	PathHMACAudit    = "tier0/hmac/audit"     // HMAC-SHA256 for audit chain
	PathAPIKeyPepper = "tier0/apikey/pepper"  // HMAC-SHA256 pepper
	PathJWTPrivate   = "tier0/jwt/private"    // RS256 PEM (private)
	PathJWTPublic    = "tier0/jwt/public"     // RS256 PEM (public)
)

// Tier 1 — Service credentials.
const (
	PathPostgresControlplane = "tier1/postgres/controlplane"
	PathPostgresAuditWriter  = "tier1/postgres/audit-worker"
	PathPostgresWorker       = "tier1/postgres/worker"
	PathPostgresReadonly     = "tier1/postgres/readonly"
	PathRedisAuth            = "tier1/redis/auth"
	PathNATSNkey             = "tier1/nats/nkey"
	PathSMTPPassword         = "tier1/smtp/password"
	PathBackupAgeRecipient   = "tier1/backup/age-recipient"
)

// AllPaths returns every defined canonical path. Used by
// paths_test.TestSecretPathsDriftCheck to keep code + doc in sync.
func AllPaths() []string {
	return []string{
		PathAESMaster, PathHMACAudit, PathAPIKeyPepper,
		PathJWTPrivate, PathJWTPublic,
		PathPostgresControlplane, PathPostgresAuditWriter,
		PathPostgresWorker, PathPostgresReadonly,
		PathRedisAuth, PathNATSNkey,
		PathSMTPPassword, PathBackupAgeRecipient,
	}
}
