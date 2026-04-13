// Package apikeys provides API key generation, hashing, and lookup for
// SentinelCore's CI/CD automation authentication. Keys use the format
// "sc_<32-random-hex>" and are stored as SHA-256 hashes. The plaintext
// is returned exactly once at creation time.
package apikeys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	keyPrefix  = "sc_"
	keyRandLen = 32 // 32 hex chars = 16 bytes of entropy
)

// Key is the public representation of an API key (never includes the secret).
type Key struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	Scopes    []string  `json:"scopes"`
	LastUsed  *string   `json:"last_used_at,omitempty"`
	ExpiresAt *string   `json:"expires_at,omitempty"`
	Revoked   bool      `json:"revoked"`
	CreatedAt string    `json:"created_at"`
}

// CreateResult is returned from Create — includes the plaintext key exactly once.
type CreateResult struct {
	Key       Key    `json:"api_key"`
	PlainText string `json:"key"` // shown once, never stored
}

// ResolvedKey is the result of looking up a key by its plaintext — used by
// the auth middleware to authenticate API requests.
type ResolvedKey struct {
	KeyID  string
	OrgID  string
	UserID string
	Scopes []string
	Role   string // looked up from users table
}

// Generate creates a new random API key string.
func Generate() string {
	b := make([]byte, keyRandLen/2)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return keyPrefix + hex.EncodeToString(b)
}

// Hash returns the SHA-256 hex digest of a key.
func Hash(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// PrefixOf returns the display prefix (first 8 chars after "sc_").
func PrefixOf(key string) string {
	if len(key) > 11 {
		return key[:11] + "…"
	}
	return key
}

// Create generates a new API key, persists the hash, and returns the
// plaintext exactly once.
func Create(ctx context.Context, pool *pgxpool.Pool, orgID, userID, name string, scopes []string, expiresAt *time.Time) (*CreateResult, error) {
	plain := Generate()
	hash := Hash(plain)
	prefix := PrefixOf(plain)
	id := uuid.New().String()

	var expStr *string
	if expiresAt != nil {
		s := expiresAt.Format(time.RFC3339)
		expStr = &s
	}

	_, err := pool.Exec(ctx,
		`INSERT INTO core.api_keys (id, org_id, user_id, name, prefix, key_hash, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, orgID, userID, name, prefix, hash, scopes, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert api key: %w", err)
	}

	return &CreateResult{
		Key: Key{
			ID:        id,
			OrgID:     orgID,
			UserID:    userID,
			Name:      name,
			Prefix:    prefix,
			Scopes:    scopes,
			ExpiresAt: expStr,
			CreatedAt: time.Now().Format(time.RFC3339),
		},
		PlainText: plain,
	}, nil
}

// Resolve looks up an API key by its plaintext value. Returns nil if the key
// is invalid, expired, or revoked. Also updates last_used_at.
func Resolve(ctx context.Context, pool *pgxpool.Pool, plainKey string) (*ResolvedKey, error) {
	if !strings.HasPrefix(plainKey, keyPrefix) {
		return nil, errors.New("invalid key format")
	}
	hash := Hash(plainKey)

	var rk ResolvedKey
	var expiresAt *time.Time
	err := pool.QueryRow(ctx,
		`SELECT k.id, k.org_id, k.user_id, k.scopes, u.role, k.expires_at
		   FROM core.api_keys k
		   JOIN core.users u ON u.id = k.user_id
		  WHERE k.key_hash = $1 AND k.revoked = false`, hash,
	).Scan(&rk.KeyID, &rk.OrgID, &rk.UserID, &rk.Scopes, &rk.Role, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if expiresAt != nil && time.Now().After(*expiresAt) {
		return nil, nil
	}

	// Update last_used_at (fire-and-forget).
	go func() {
		pool.Exec(context.Background(),
			`UPDATE core.api_keys SET last_used_at = now() WHERE id = $1`, rk.KeyID)
	}()

	return &rk, nil
}

// List returns all API keys for an org (never returns hashes or plaintexts).
func List(ctx context.Context, pool *pgxpool.Pool, orgID string) ([]Key, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, org_id, user_id, name, prefix, scopes, last_used_at, expires_at, revoked, created_at
		   FROM core.api_keys WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []Key
	for rows.Next() {
		var k Key
		var lastUsed *time.Time
		var expiresAt *time.Time
		var createdAt time.Time
		if sErr := rows.Scan(&k.ID, &k.OrgID, &k.UserID, &k.Name, &k.Prefix,
			&k.Scopes, &lastUsed, &expiresAt, &k.Revoked, &createdAt); sErr != nil {
			return nil, sErr
		}
		if lastUsed != nil {
			s := lastUsed.Format(time.RFC3339)
			k.LastUsed = &s
		}
		if expiresAt != nil {
			s := expiresAt.Format(time.RFC3339)
			k.ExpiresAt = &s
		}
		k.CreatedAt = createdAt.Format(time.RFC3339)
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []Key{}
	}
	return keys, rows.Err()
}

// Revoke marks an API key as revoked. It cannot be used again.
func Revoke(ctx context.Context, pool *pgxpool.Pool, keyID, orgID string) error {
	tag, err := pool.Exec(ctx,
		`UPDATE core.api_keys SET revoked = true WHERE id = $1 AND org_id = $2`, keyID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("key not found")
	}
	return nil
}
