package crypto

// envelope.go — versioned AES-256-GCM envelope encryption keyed off the
// auth.aes_keys catalog introduced by migration 039.
//
// Wire format:
//
//   enc:v<N>:<purpose>:<b64(nonce||ciphertext||tag)>
//
// Example:  enc:v1:sso:b5oN…==
//
// The leading "enc:v" prefix is the format version, deliberately
// different from (but compatible with) the legacy "enc:v1:" prefix used
// by pkg/sso before Phase 7. The migration helper MigrateLegacy accepts
// both forms so running systems can decrypt in-place.
//
// Key material itself is NOT in the catalog — the DB row only records
// the version, purpose, vault path (env:FOO or vault://...), and a
// sha256 fingerprint of the raw key. The Envelope is constructed with
// a KeyResolver that turns (purpose, version) into the 32-byte key.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Purpose is a short tag grouping AES keys by feature. Matches the
// CHECK constraint on auth.aes_keys.purpose.
type Purpose string

const (
	PurposeSSO          Purpose = "sso"
	PurposeWebhook      Purpose = "webhook"
	PurposeAuthProfile  Purpose = "auth_profile"
	PurposeIntegration  Purpose = "integration"
	PurposeGeneric      Purpose = "generic"
)

// ErrUnknownKey is returned when a ciphertext references a version not
// in the catalog. Usually means a partial restore from a newer backup.
var ErrUnknownKey = errors.New("crypto: envelope key version not found")

// ErrBadEnvelope is returned when a string is not a well-formed envelope.
var ErrBadEnvelope = errors.New("crypto: malformed envelope")

// KeyResolver fetches the raw 32-byte AES key for a (purpose, version).
// Implementations typically delegate to a secrets.Resolver with the
// vault_path column from auth.aes_keys as the path.
type KeyResolver interface {
	ResolveKey(ctx context.Context, purpose Purpose, version int) ([]byte, error)
}

// Envelope encrypts with the current version for a purpose and
// decrypts any catalog-known version. It caches resolved keys in
// memory for the process lifetime; rotation invalidates via Reload.
type Envelope struct {
	pool   *pgxpool.Pool
	keys   KeyResolver

	mu       sync.RWMutex
	aeads    map[Purpose]map[int]*AESGCM // purpose→version→aead
	current  map[Purpose]int             // purpose→highest-known version
}

// NewEnvelope constructs an Envelope. Call Reload once before first
// use to warm the cache from the catalog; callers that skip it will
// incur a DB lookup on the first Seal/Open.
func NewEnvelope(pool *pgxpool.Pool, keys KeyResolver) *Envelope {
	return &Envelope{
		pool:    pool,
		keys:    keys,
		aeads:   map[Purpose]map[int]*AESGCM{},
		current: map[Purpose]int{},
	}
}

// Reload rescans auth.aes_keys and rebuilds the in-memory cache. Safe
// to call concurrently with Seal/Open — the swap is atomic under the
// internal lock.
func (e *Envelope) Reload(ctx context.Context) error {
	rows, err := e.pool.Query(ctx,
		`SELECT version, purpose FROM auth.aes_keys ORDER BY purpose, version`)
	if err != nil {
		return fmt.Errorf("envelope reload query: %w", err)
	}
	defer rows.Close()

	newAeads := map[Purpose]map[int]*AESGCM{}
	newCurrent := map[Purpose]int{}
	for rows.Next() {
		var version int
		var purpose string
		if err := rows.Scan(&version, &purpose); err != nil {
			return fmt.Errorf("envelope reload scan: %w", err)
		}
		p := Purpose(purpose)
		key, err := e.keys.ResolveKey(ctx, p, version)
		if err != nil {
			return fmt.Errorf("envelope resolve %s v%d: %w", p, version, err)
		}
		aead, err := NewAESGCM(key)
		if err != nil {
			return fmt.Errorf("envelope aesgcm %s v%d: %w", p, version, err)
		}
		if newAeads[p] == nil {
			newAeads[p] = map[int]*AESGCM{}
		}
		newAeads[p][version] = aead
		if version > newCurrent[p] {
			newCurrent[p] = version
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	e.mu.Lock()
	e.aeads = newAeads
	e.current = newCurrent
	e.mu.Unlock()
	return nil
}

// Seal encrypts plaintext with the current version for purpose and
// returns the envelope string. aad binds the ciphertext to a logical
// context (e.g. provider.id) — pass nil if binding is not needed.
func (e *Envelope) Seal(purpose Purpose, plaintext, aad []byte) (string, error) {
	e.mu.RLock()
	ver := e.current[purpose]
	aead, ok := e.aeads[purpose][ver]
	e.mu.RUnlock()
	if !ok || ver == 0 {
		return "", fmt.Errorf("envelope: no current key for purpose %q — call Reload", purpose)
	}
	blob, err := aead.Seal(plaintext, aad)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("enc:v%d:%s:%s", ver, purpose,
		base64.StdEncoding.EncodeToString(blob)), nil
}

// Open decrypts an envelope. Unknown versions return ErrUnknownKey so
// callers can distinguish "catalog is stale" from "ciphertext tampered".
func (e *Envelope) Open(envelope string, aad []byte) ([]byte, error) {
	ver, purpose, blob, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	e.mu.RLock()
	aead, ok := e.aeads[purpose][ver]
	e.mu.RUnlock()
	if !ok {
		return nil, ErrUnknownKey
	}
	return aead.Open(blob, aad)
}

// CurrentVersion returns the highest-known version for a purpose, or 0
// if none. Handy for metrics/log context when rotating.
func (e *Envelope) CurrentVersion(purpose Purpose) int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.current[purpose]
}

// parseEnvelope splits "enc:v<N>:<purpose>:<b64>" into its parts.
// Returns ErrBadEnvelope on any structural error — the caller should
// treat that as "not an envelope" and refuse to decrypt.
func parseEnvelope(s string) (int, Purpose, []byte, error) {
	if !strings.HasPrefix(s, "enc:v") {
		return 0, "", nil, ErrBadEnvelope
	}
	// Strip "enc:v" then split into ver, purpose, body (exactly three parts).
	rest := s[len("enc:v"):]
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) != 3 {
		return 0, "", nil, ErrBadEnvelope
	}
	ver, err := strconv.Atoi(parts[0])
	if err != nil || ver <= 0 {
		return 0, "", nil, ErrBadEnvelope
	}
	purpose := Purpose(parts[1])
	blob, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, "", nil, ErrBadEnvelope
	}
	return ver, purpose, blob, nil
}
