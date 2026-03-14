package updater

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RootPublicKey represents the pinned root public key.
type RootPublicKey struct {
	Format      string `json:"format"`
	Version     int    `json:"format_version"`
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"`   // base64-encoded Ed25519 public key
	Fingerprint string `json:"fingerprint"` // sha256:<hex>
	CreatedAt   string `json:"created_at"`
}

// SigningKeyCert represents a signing key certificate signed by the root key.
type SigningKeyCert struct {
	Format              string `json:"format"`
	FormatVersion       int    `json:"format_version"`
	Serial              string `json:"serial"`
	Purpose             string `json:"purpose"` // platform_signing, rule_signing, vuln_intel_signing
	PublicKey           string `json:"public_key"` // base64
	ValidFrom           string `json:"valid_from"`
	ValidUntil          string `json:"valid_until"`
	IssuedAt            string `json:"issued_at"`
	IssuedByFingerprint string `json:"issued_by_root_fingerprint"`
	ReplacesSerial      string `json:"replaces_serial,omitempty"`
	Metadata            any    `json:"metadata,omitempty"`
}

// TrustStore manages the trust chain: root public key, signing certificates,
// and trust state persistence.
type TrustStore struct {
	trustDir string
	pool     *pgxpool.Pool
}

// NewTrustStore creates a new TrustStore backed by a filesystem directory
// (for the pinned root key) and a PostgreSQL pool (for trust state).
func NewTrustStore(trustDir string, pool *pgxpool.Pool) *TrustStore {
	return &TrustStore{trustDir: trustDir, pool: pool}
}

// LoadRootPublicKey reads the pinned root public key from disk.
func (ts *TrustStore) LoadRootPublicKey() (*RootPublicKey, error) {
	data, err := os.ReadFile(filepath.Join(ts.trustDir, "root_pubkey.json"))
	if err != nil {
		return nil, err
	}
	var key RootPublicKey
	return &key, json.Unmarshal(data, &key)
}

// GetTrustState returns all key-value pairs from the updates.trust_state table.
func (ts *TrustStore) GetTrustState(ctx context.Context) (map[string]string, error) {
	rows, err := ts.pool.Query(ctx, "SELECT key, value FROM updates.trust_state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	state := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		state[k] = v
	}
	return state, rows.Err()
}

// SetTrustState updates a single key in the trust state table.
func (ts *TrustStore) SetTrustState(ctx context.Context, key, value string) error {
	_, err := ts.pool.Exec(ctx,
		"UPDATE updates.trust_state SET value = $1, updated_at = now() WHERE key = $2",
		value, key)
	return err
}
