// Package credentials provides envelope-encrypted storage for DAST replay
// credentials. Each row in dast_credential_secrets holds a single secret
// keyed by (bundle_id, vault_key); plaintext is never persisted.
//
// Credentials are encrypted via internal/kms.EncryptEnvelope using AAD =
// bundle_id "|" vault_key, so a row tampered to point at a different bundle
// will fail GCM authentication on Load.
package credentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/kms"
	"github.com/sentinelcore/sentinelcore/internal/metrics"
)

// ErrNotFound is returned by Load when no row matches (bundle_id, vault_key).
var ErrNotFound = errors.New("credentials: not found")

// Store is the persistence interface for DAST replay credentials.
type Store interface {
	// Save encrypts plaintext and inserts (or upserts on conflict) the row
	// keyed by (bundleID, vaultKey) for the given customer.
	Save(ctx context.Context, customerID, bundleID uuid.UUID, vaultKey string, plaintext []byte) error
	// Load decrypts and returns the credential value identified by
	// (bundleID, vaultKey). Returns ErrNotFound if no such row exists.
	Load(ctx context.Context, bundleID uuid.UUID, vaultKey string) ([]byte, error)
	// Delete removes the row identified by (bundleID, vaultKey). Deleting a
	// missing row is not an error.
	Delete(ctx context.Context, bundleID uuid.UUID, vaultKey string) error
	// ListKeys returns the vault_keys (sorted ascending) for a bundle.
	ListKeys(ctx context.Context, bundleID uuid.UUID) ([]string, error)
}

// PostgresStore is a Store backed by PostgreSQL with envelope encryption via
// a kms.Provider.
type PostgresStore struct {
	pool *pgxpool.Pool
	kms  kms.Provider
}

// NewPostgresStore creates a PostgresStore ready for use.
func NewPostgresStore(pool *pgxpool.Pool, p kms.Provider) *PostgresStore {
	return &PostgresStore{pool: pool, kms: p}
}

// aadFor returns the additional authenticated data binding a credential row
// to its (bundleID, vaultKey) pair. Mutating either component in the database
// causes Load's GCM Open to fail authentication.
func aadFor(bundleID uuid.UUID, vaultKey string) []byte {
	return []byte(bundleID.String() + "|" + vaultKey)
}

// Save encrypts plaintext under a fresh DEK and persists the row. On conflict
// (same bundle_id + vault_key) it overwrites the existing row.
func (s *PostgresStore) Save(ctx context.Context, customerID, bundleID uuid.UUID, vaultKey string, plaintext []byte) error {
	if vaultKey == "" {
		return fmt.Errorf("credentials/save: vault_key required")
	}
	env, err := kms.EncryptEnvelope(ctx, s.kms, "dast.credential", plaintext, aadFor(bundleID, vaultKey))
	if err != nil {
		return fmt.Errorf("credentials/save: encrypt: %w", err)
	}
	// kms.EncryptEnvelope appends the GCM auth tag to env.Ciphertext, so
	// aead_tag is stored as an empty byte slice. The migration declares the
	// column NOT NULL but allows zero-length BYTEA. We keep the column for
	// potential future split-tag formats while preserving compatibility.
	_, err = s.pool.Exec(ctx, `
		INSERT INTO dast_credential_secrets
		    (bundle_id, vault_key, customer_id, iv, ciphertext, aead_tag, wrapped_dek)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (bundle_id, vault_key) DO UPDATE
		SET iv          = EXCLUDED.iv,
		    ciphertext  = EXCLUDED.ciphertext,
		    aead_tag    = EXCLUDED.aead_tag,
		    wrapped_dek = EXCLUDED.wrapped_dek`,
		bundleID, vaultKey, customerID,
		env.IV, env.Ciphertext, []byte{}, env.WrappedDEK)
	if err != nil {
		return fmt.Errorf("credentials/save: insert: %w", err)
	}
	return nil
}

// Load reads the row for (bundleID, vaultKey) and decrypts its ciphertext.
func (s *PostgresStore) Load(ctx context.Context, bundleID uuid.UUID, vaultKey string) ([]byte, error) {
	var (
		iv, ciphertext, wrappedDEK []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT iv, ciphertext, wrapped_dek
		FROM dast_credential_secrets
		WHERE bundle_id = $1 AND vault_key = $2`,
		bundleID, vaultKey,
	).Scan(&iv, &ciphertext, &wrappedDEK)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			metrics.CredentialLoadTotal.WithLabelValues("not_found").Inc()
			return nil, ErrNotFound
		}
		metrics.CredentialLoadTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("credentials/load: scan: %w", err)
	}
	env := &kms.Envelope{
		IV:         iv,
		Ciphertext: ciphertext,
		WrappedDEK: wrappedDEK,
		// LocalProvider ignores key version; AWS provider stores it but we
		// do not currently round-trip the value because all rows are wrapped
		// under the active KEK.
	}
	plain, err := kms.DecryptEnvelope(ctx, s.kms, env, aadFor(bundleID, vaultKey))
	if err != nil {
		metrics.CredentialLoadTotal.WithLabelValues("decrypt_error").Inc()
		return nil, fmt.Errorf("credentials/load: decrypt: %w", err)
	}
	metrics.CredentialLoadTotal.WithLabelValues("success").Inc()
	return plain, nil
}

// Delete removes the row identified by (bundleID, vaultKey). Missing rows
// silently succeed.
func (s *PostgresStore) Delete(ctx context.Context, bundleID uuid.UUID, vaultKey string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM dast_credential_secrets WHERE bundle_id = $1 AND vault_key = $2`,
		bundleID, vaultKey)
	if err != nil {
		return fmt.Errorf("credentials/delete: %w", err)
	}
	return nil
}

// ListKeys returns the vault_keys (sorted) for a bundle.
func (s *PostgresStore) ListKeys(ctx context.Context, bundleID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT vault_key FROM dast_credential_secrets WHERE bundle_id = $1 ORDER BY vault_key`,
		bundleID)
	if err != nil {
		return nil, fmt.Errorf("credentials/list: query: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("credentials/list: scan: %w", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("credentials/list: rows: %w", err)
	}
	return out, nil
}

// Compile-time interface satisfaction.
var _ Store = (*PostgresStore)(nil)
