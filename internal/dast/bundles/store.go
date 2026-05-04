package bundles

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// Sentinel errors returned by BundleStore operations.
var (
	ErrBundleNotFound   = errors.New("bundles: bundle not found")
	ErrBundleUnusable   = errors.New("bundles: bundle not usable")
	ErrIntegrityFailure = errors.New("bundles: integrity HMAC mismatch")
)

// AuditWriter writes a single audit event. We avoid importing internal/audit
// directly to keep this package decoupled — controlplane wires the real
// writer at startup.
type AuditWriter interface {
	Write(ctx context.Context, eventType string, resourceID string, details map[string]any) error
}

type noopAudit struct{}

func (noopAudit) Write(_ context.Context, _ string, _ string, _ map[string]any) error { return nil }

// BundleStore defines the persistence and lifecycle operations for auth bundles.
type BundleStore interface {
	// Save encrypts and persists b for the given customer. Returns the bundle ID.
	Save(ctx context.Context, b *Bundle, customerID string) (string, error)
	// Load decrypts and returns the bundle identified by id and customerID.
	Load(ctx context.Context, id, customerID string) (*Bundle, error)
	// UpdateStatus sets the lifecycle status of a bundle.
	UpdateStatus(ctx context.Context, id, status string) error
	// Revoke marks a bundle as revoked, zeroes the wrapped DEK, and records reason.
	Revoke(ctx context.Context, id, reason string) error
	// SoftDelete marks a bundle soft-deleted and schedules hard deletion.
	SoftDelete(ctx context.Context, id string) error
	// IncUseCount increments the use_count counter and updates last_used_at.
	IncUseCount(ctx context.Context, id string) error
	// AddACL grants a project (and optional scope) access to a bundle.
	AddACL(ctx context.Context, bundleID, projectID string, scopeID *string) error
	// CheckACL returns true if the project (and optional scope) has ACL access.
	CheckACL(ctx context.Context, bundleID, projectID string, scopeID *string) (bool, error)
	// Approve transitions a bundle from pending_review to approved.
	// The Postgres 4-eyes trigger rejects approval by the recorder.
	Approve(ctx context.Context, id, reviewerUserID string, ttlSeconds int) error
	// Reject transitions a bundle from pending_review to revoked.
	Reject(ctx context.Context, id, reviewerUserID, reason string) error
	// ListPending returns BundleSummary for bundles in pending_review status.
	ListPending(ctx context.Context, customerID string, offset, limit int) ([]*BundleSummary, error)
}

// ObjectStore is the interface for out-of-band ciphertext blob storage. For
// environments where ciphertext is stored inline in the DB, InlineObjectStore
// is used instead.
type ObjectStore interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

// InlineObjectStore is a no-op ObjectStore used when ciphertext lives inline
// in the database row (prefixed with "inline:" + base64). Put and Delete are
// no-ops; Get returns an error because inline refs are resolved by the store
// directly without calling ObjectStore.Get.
type InlineObjectStore struct{}

func (InlineObjectStore) Put(_ context.Context, _ string, _ []byte) error { return nil }
func (InlineObjectStore) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("inline object store: Get should not be called for inline refs")
}
func (InlineObjectStore) Delete(_ context.Context, _ string) error { return nil }

// PostgresStore is a BundleStore backed by a PostgreSQL connection pool with
// envelope encryption via a kms.Provider and integrity HMAC.
type PostgresStore struct {
	pool        *pgxpool.Pool
	kms         kms.Provider
	hmacKeyPath string
	masterKeyID string
	objectStore ObjectStore
	now         func() time.Time
	audit       AuditWriter
}

// NewPostgresStore creates a PostgresStore ready for use.
func NewPostgresStore(pool *pgxpool.Pool, k kms.Provider, hmacKeyPath, masterKeyID string, obj ObjectStore) *PostgresStore {
	return &PostgresStore{
		pool:        pool,
		kms:         k,
		hmacKeyPath: hmacKeyPath,
		masterKeyID: masterKeyID,
		objectStore: obj,
		now:         time.Now,
		audit:       noopAudit{},
	}
}

// SetAuditWriter wires an AuditWriter for recording lifecycle events.
// Passing nil resets to the no-op implementation.
func (s *PostgresStore) SetAuditWriter(w AuditWriter) {
	if w == nil {
		w = noopAudit{}
	}
	s.audit = w
}

// Save encrypts b and inserts it into dast_auth_bundles. Returns the assigned bundle ID.
func (s *PostgresStore) Save(ctx context.Context, b *Bundle, customerID string) (string, error) {
	// 1. Generate ID if missing.
	if b.ID == "" {
		b.ID = uuid.New().String()
	}

	// 2. Set schema version and customer.
	b.SchemaVersion = 1
	b.CustomerID = customerID

	// 3. Set CreatedAt if zero.
	if b.CreatedAt.IsZero() {
		b.CreatedAt = s.now()
	}

	// 4. Set ExpiresAt if zero.
	if b.ExpiresAt.IsZero() {
		ttl := b.TTLSeconds
		if ttl <= 0 {
			ttl = 86400
		}
		b.ExpiresAt = b.CreatedAt.Add(time.Duration(ttl) * time.Second)
	}

	// 5. Compute canonical JSON.
	canonical, err := b.CanonicalJSON()
	if err != nil {
		return "", fmt.Errorf("bundles/save: canonical JSON: %w", err)
	}

	// 6. Build AAD.
	aad := []byte(fmt.Sprintf("%s|v%d", b.ID, b.SchemaVersion))

	// 7. Encrypt via KMS envelope.
	env, err := kms.EncryptEnvelope(ctx, s.kms, "dast_bundle", canonical, aad)
	if err != nil {
		return "", fmt.Errorf("bundles/save: encrypt: %w", err)
	}

	// 8. Integrity HMAC over ciphertext ‖ aad.
	hmacMsg := append(env.Ciphertext, aad...)
	integrityHMAC, err := s.kms.HMAC(ctx, s.hmacKeyPath, hmacMsg)
	if err != nil {
		return "", fmt.Errorf("bundles/save: compute HMAC: %w", err)
	}

	// 9. Inline storage: ciphertext_ref = "inline:" + base64(ciphertext).
	ctRef := "inline:" + base64.StdEncoding.EncodeToString(env.Ciphertext)

	// 10. Marshal recording_metadata for DB column (NULL for session_import).
	var recordingMetadataJSON []byte
	if b.RecordingMetadata != nil {
		recordingMetadataJSON, err = json.Marshal(b.RecordingMetadata)
		if err != nil {
			return "", fmt.Errorf("bundles/save: marshal recording_metadata: %w", err)
		}
	}

	// 11. Insert row.
	const q = `
INSERT INTO dast_auth_bundles (
    id, customer_id, project_id, target_host, target_principal,
    type, status,
    iv, ciphertext_ref, wrapped_dek, kms_key_id, kms_key_version,
    integrity_hmac, schema_version,
    created_by_user_id, created_at, expires_at,
    captcha_in_flow, automatable_refresh, ttl_seconds,
    recording_metadata
) VALUES (
    $1, $2, $3, $4, $5,
    $6, 'pending_review',
    $7, $8, $9, $10, $11,
    $12, $13,
    $14, $15, $16,
    $17, $18, $19,
    $20
)`
	_, err = s.pool.Exec(ctx, q,
		b.ID, b.CustomerID, b.ProjectID, b.TargetHost, nullableString(b.TargetPrincipal),
		b.Type,
		env.IV, ctRef, env.WrappedDEK, s.masterKeyID, env.KeyVersion,
		integrityHMAC, b.SchemaVersion,
		b.CreatedByUserID, b.CreatedAt, b.ExpiresAt,
		b.CaptchaInFlow, b.AutomatableRefresh, b.TTLSeconds,
		nullableBytes(recordingMetadataJSON),
	)
	if err != nil {
		return "", fmt.Errorf("bundles/save: insert: %w", err)
	}

	// 11. Emit audit event (best-effort; ignore error).
	_ = s.audit.Write(ctx, "dast.recording.created", b.ID, map[string]any{
		"target_host": b.TargetHost,
		"type":        b.Type,
		"customer_id": customerID,
		"project_id":  b.ProjectID,
	})

	// 12. Return bundle ID.
	return b.ID, nil
}

// Load decrypts and reconstructs a Bundle from the database.
func (s *PostgresStore) Load(ctx context.Context, id, customerID string) (*Bundle, error) {
	// 1. SELECT the row.
	const q = `
SELECT
    id, customer_id, project_id, target_host, target_principal,
    type, status, schema_version,
    iv, ciphertext_ref, wrapped_dek, kms_key_version,
    integrity_hmac,
    created_by_user_id, created_at, expires_at,
    captcha_in_flow, automatable_refresh, ttl_seconds,
    recording_metadata
FROM dast_auth_bundles
WHERE id = $1 AND customer_id = $2`

	row := s.pool.QueryRow(ctx, q, id, customerID)

	var (
		bID, bCustomerID, bProjectID, bTargetHost string
		bTargetPrincipal                           *string
		bType, bStatus                             string
		bSchemaVersion                             int
		ivBytes, wrappedDEK, integrityHMAC         []byte
		ciphertextRef, kmsKeyVersion               string
		createdByUserID                            string
		createdAt, expiresAt                       time.Time
		captchaInFlow, automatableRefresh          bool
		ttlSeconds                                 int
		recordingMetadataRaw                       []byte
	)

	err := row.Scan(
		&bID, &bCustomerID, &bProjectID, &bTargetHost, &bTargetPrincipal,
		&bType, &bStatus, &bSchemaVersion,
		&ivBytes, &ciphertextRef, &wrappedDEK, &kmsKeyVersion,
		&integrityHMAC,
		&createdByUserID, &createdAt, &expiresAt,
		&captchaInFlow, &automatableRefresh, &ttlSeconds,
		&recordingMetadataRaw,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrBundleNotFound
		}
		return nil, fmt.Errorf("bundles/load: scan: %w", err)
	}

	// 2. Reject unusable statuses.
	switch bStatus {
	case "revoked", "soft_deleted", "expired":
		return nil, fmt.Errorf("%w: status=%s", ErrBundleUnusable, bStatus)
	}

	// 3. Extract ciphertext.
	var ciphertext []byte
	if strings.HasPrefix(ciphertextRef, "inline:") {
		encoded := ciphertextRef[len("inline:"):]
		ciphertext, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("bundles/load: decode inline ciphertext: %w", err)
		}
	} else {
		ciphertext, err = s.objectStore.Get(ctx, ciphertextRef)
		if err != nil {
			return nil, fmt.Errorf("bundles/load: object store get: %w", err)
		}
	}

	// 4. Verify integrity HMAC.
	aad := []byte(fmt.Sprintf("%s|v%d", bID, bSchemaVersion))
	hmacMsg := append(ciphertext, aad...)
	ok, err := s.kms.HMACVerify(ctx, s.hmacKeyPath, hmacMsg, integrityHMAC)
	if err != nil {
		return nil, fmt.Errorf("bundles/load: HMAC verify: %w", err)
	}
	if !ok {
		_ = s.audit.Write(ctx, "dast.recording.integrity_failed", id, map[string]any{
			"customer_id": customerID,
		})
		return nil, ErrIntegrityFailure
	}

	// 5. Reconstruct envelope.
	env := &kms.Envelope{
		Ciphertext: ciphertext,
		IV:         ivBytes,
		WrappedDEK: wrappedDEK,
		KeyVersion: kmsKeyVersion,
	}

	// 6. Decrypt.
	plaintext, err := kms.DecryptEnvelope(ctx, s.kms, env, aad)
	if err != nil {
		return nil, fmt.Errorf("bundles/load: decrypt: %w", err)
	}

	// 7. Unmarshal.
	var b Bundle
	if err := json.Unmarshal(plaintext, &b); err != nil {
		return nil, fmt.Errorf("bundles/load: unmarshal: %w", err)
	}

	// Restore DB-sourced fields that may not be in the encrypted payload.
	b.ID = bID
	b.CustomerID = bCustomerID
	if bTargetPrincipal != nil {
		b.TargetPrincipal = *bTargetPrincipal
	}

	// recording_metadata: prefer the decrypted blob's value (already in b if
	// it was serialized there). If the blob predates the field, fall back to
	// the DB column.
	if b.RecordingMetadata == nil && len(recordingMetadataRaw) > 0 {
		var rm RecordingMetadata
		if err := json.Unmarshal(recordingMetadataRaw, &rm); err == nil {
			b.RecordingMetadata = &rm
		}
	}

	// 8. Emit audit event (best-effort; ignore error).
	_ = s.audit.Write(ctx, "dast.recording.accessed", id, map[string]any{
		"customer_id": customerID,
	})

	// 9. Return.
	return &b, nil
}

// UpdateStatus sets the lifecycle status of the bundle with the given ID.
// Returns ErrBundleNotFound if no row was updated.
func (s *PostgresStore) UpdateStatus(ctx context.Context, id, status string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE dast_auth_bundles SET status = $2 WHERE id = $1`, id, status)
	if err != nil {
		return fmt.Errorf("bundles/update-status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrBundleNotFound
	}
	return nil
}

// Revoke marks a bundle as revoked, zeroes the wrapped DEK to prevent future
// decryption, and records the reason in metadata_jsonb.
func (s *PostgresStore) Revoke(ctx context.Context, id, reason string) error {
	reasonJSON, _ := json.Marshal(reason)
	const q = `
UPDATE dast_auth_bundles
SET
    status      = 'revoked',
    revoked_at  = now(),
    wrapped_dek = '\x00'::bytea,
    metadata_jsonb = metadata_jsonb || jsonb_build_object('revoke_reason', $2::jsonb)
WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id, string(reasonJSON))
	if err != nil {
		return fmt.Errorf("bundles/revoke: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrBundleNotFound
	}
	_ = s.audit.Write(ctx, "dast.recording.revoked", id, map[string]any{
		"reason": reason,
	})
	return nil
}

// SoftDelete marks a bundle soft-deleted and schedules hard deletion 30 days later.
func (s *PostgresStore) SoftDelete(ctx context.Context, id string) error {
	const q = `
UPDATE dast_auth_bundles
SET
    status          = 'soft_deleted',
    soft_deleted_at = now(),
    hard_delete_after = now() + INTERVAL '30 days'
WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("bundles/soft-delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrBundleNotFound
	}
	return nil
}

// IncUseCount increments use_count and sets last_used_at = now().
func (s *PostgresStore) IncUseCount(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE dast_auth_bundles SET use_count = use_count + 1, last_used_at = now() WHERE id = $1`,
		id)
	if err != nil {
		return fmt.Errorf("bundles/inc-use-count: %w", err)
	}
	_ = s.audit.Write(ctx, "dast.recording.used", id, nil)
	return nil
}

// AddACL grants (bundleID, projectID, scopeID) access. Duplicates are silently
// ignored via ON CONFLICT DO NOTHING.
func (s *PostgresStore) AddACL(ctx context.Context, bundleID, projectID string, scopeID *string) error {
	var err error
	if scopeID == nil {
		_, err = s.pool.Exec(ctx,
			`INSERT INTO dast_auth_bundle_acls (bundle_id, project_id, scope_id)
             VALUES ($1, $2, NULL)
             ON CONFLICT DO NOTHING`,
			bundleID, projectID)
	} else {
		_, err = s.pool.Exec(ctx,
			`INSERT INTO dast_auth_bundle_acls (bundle_id, project_id, scope_id)
             VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING`,
			bundleID, projectID, *scopeID)
	}
	if err != nil {
		return fmt.Errorf("bundles/add-acl: %w", err)
	}
	return nil
}

// CheckACL returns true if the bundle has an ACL entry matching (bundleID,
// projectID) and either scope_id IS NULL or scope_id = scopeID.
func (s *PostgresStore) CheckACL(ctx context.Context, bundleID, projectID string, scopeID *string) (bool, error) {
	var count int
	var err error
	if scopeID == nil {
		err = s.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM dast_auth_bundle_acls
             WHERE bundle_id = $1 AND project_id = $2 AND scope_id IS NULL`,
			bundleID, projectID).Scan(&count)
	} else {
		err = s.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM dast_auth_bundle_acls
             WHERE bundle_id = $1 AND project_id = $2
               AND (scope_id IS NULL OR scope_id = $3)`,
			bundleID, projectID, *scopeID).Scan(&count)
	}
	if err != nil {
		return false, fmt.Errorf("bundles/check-acl: %w", err)
	}
	return count > 0, nil
}

// nullableString converts an empty Go string to a typed nil (SQL NULL).
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nullableBytes returns nil (SQL NULL) for an empty/nil slice, otherwise the slice.
func nullableBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// Ensure compile-time interface satisfaction.
var _ BundleStore = (*PostgresStore)(nil)

// Ensure sql package is referenced to satisfy import requirements in CI tools
// that enforce used imports.
var _ = sql.ErrNoRows
