package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// KeyResolver returns HMAC key material for a given version. Implementations:
//
//   - EnvKeyResolver  — reads AUDIT_HMAC_KEY_B64 for version 1 only;
//     transitional until Vault is wired.
//   - (future) VaultKeyResolver — fetches vault_path from audit.hmac_keys
//     and caches in process memory.
//
// The verifier and the writer share one resolver instance so a key lookup
// miss on the writer hot path surfaces the same audit.hmac_key.missing
// event the verifier would emit.
type KeyResolver interface {
	Key(version int) ([]byte, error)
	CurrentVersion() int
}

// ErrKeyMissing is returned when a KeyResolver cannot find a requested version.
// Callers errors.Is-check this so the audit.hmac_key.missing action code
// can be emitted cleanly.
var ErrKeyMissing = errors.New("audit: HMAC key version not found")

// EnvKeyResolver is the transitional resolver: base64-decoded key from
// AUDIT_HMAC_KEY_B64, version always 1. If the env var is unset or the
// decoded bytes are not 32 long, construction fails — the audit-worker
// exits rather than writing an unverifiable chain.
type EnvKeyResolver struct {
	key []byte
}

// NewEnvKeyResolver reads AUDIT_HMAC_KEY_B64 and returns a resolver. The
// caller passes raw os.Getenv output so tests can inject values directly
// via NewEnvKeyResolverFromBase64 instead.
func NewEnvKeyResolver() (*EnvKeyResolver, error) {
	return NewEnvKeyResolverFromBase64(os.Getenv("AUDIT_HMAC_KEY_B64"))
}

// NewEnvKeyResolverFromBase64 is the test-friendly constructor.
func NewEnvKeyResolverFromBase64(b64 string) (*EnvKeyResolver, error) {
	if b64 == "" {
		return nil, fmt.Errorf("%w: AUDIT_HMAC_KEY_B64 not set", ErrKeyMissing)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("audit: AUDIT_HMAC_KEY_B64 is not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("audit: AUDIT_HMAC_KEY_B64 must decode to 32 bytes, got %d", len(raw))
	}
	return &EnvKeyResolver{key: raw}, nil
}

// Key returns the env-loaded key for version 1. Other versions are not
// supported by this resolver; they belong to VaultKeyResolver.
func (r *EnvKeyResolver) Key(version int) ([]byte, error) {
	if version != 1 {
		return nil, fmt.Errorf("%w: version %d (EnvKeyResolver only has v1)",
			ErrKeyMissing, version)
	}
	return r.key, nil
}

// CurrentVersion is always 1 for the env resolver.
func (r *EnvKeyResolver) CurrentVersion() int { return 1 }

// Fingerprint returns the SHA-256 hex of the key material, for persistence
// into audit.hmac_keys.fingerprint. Does NOT reveal the key itself.
func (r *EnvKeyResolver) Fingerprint() string {
	sum := sha256.Sum256(r.key)
	return hex.EncodeToString(sum[:])
}
