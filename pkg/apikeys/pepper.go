package apikeys

// pepper.go — HMAC-SHA256 + pepper verifier for API keys. Upgrades the
// legacy SHA-256 hash scheme to a keyed MAC so that a DB leak alone
// does not let an attacker brute-force key material: they'd also need
// the pepper secret held in env (Wave 2) / Vault (Wave 3).
//
// Wire format of the verifier column:
//
//   v1:<base64(HMAC-SHA256(pepper, "v1|" || plaintext))>
//
// The "v1|" prefix binds the MAC to its version so rotating the pepper
// to v2 produces an incompatible MAC for any key signed with v1 —
// useful for detecting "wrong pepper on verify" vs. "correct pepper on
// a key older than this deployment".

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// currentPepper caches the pepper bytes and version resolved at
// startup. A second call with the same version returns the cache; a
// bump triggers a reload from the env/vault.
var (
	pepperMu      sync.RWMutex
	pepperBytes   []byte
	pepperVersion int
)

// ErrPepperMissing is returned when SC_APIKEY_PEPPER_B64 is unset.
var ErrPepperMissing = errors.New("apikeys: SC_APIKEY_PEPPER_B64 not set")

// ErrWrongPepper is returned when a verifier decodes but the MAC
// doesn't match — either tampered DB row, or pepper was rotated
// without running the backfill.
var ErrWrongPepper = errors.New("apikeys: verifier MAC mismatch")

// LoadPepper reads the pepper from env and caches it as version v.
// Call once at service startup. Safe to call again to rotate.
func LoadPepper(v int) error {
	if v < 1 {
		return fmt.Errorf("apikeys: pepper version must be >= 1, got %d", v)
	}
	raw := os.Getenv("SC_APIKEY_PEPPER_B64")
	if raw == "" {
		return ErrPepperMissing
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("apikeys: decode pepper: %w", err)
	}
	if len(b) < 32 {
		return fmt.Errorf("apikeys: pepper must be >= 32 bytes, got %d", len(b))
	}
	pepperMu.Lock()
	pepperBytes = b
	pepperVersion = v
	pepperMu.Unlock()
	return nil
}

// Verifier computes the HMAC-SHA256 verifier string for a plaintext key.
// Returns ErrPepperMissing if LoadPepper was never called.
func Verifier(plain string) (string, error) {
	pepperMu.RLock()
	defer pepperMu.RUnlock()
	if len(pepperBytes) == 0 {
		return "", ErrPepperMissing
	}
	mac := hmac.New(sha256.New, pepperBytes)
	// Bind to version so v2 pepper never validates v1 MAC and vice versa.
	_, _ = mac.Write([]byte(fmt.Sprintf("v%d|", pepperVersion)))
	_, _ = mac.Write([]byte(plain))
	sum := mac.Sum(nil)
	return fmt.Sprintf("v%d:%s", pepperVersion,
		base64.StdEncoding.EncodeToString(sum)), nil
}

// PepperVersion returns the currently loaded version, or 0 if not loaded.
func PepperVersion() int {
	pepperMu.RLock()
	defer pepperMu.RUnlock()
	return pepperVersion
}

// VerifyVerifier returns (ok, err). ok=true means the verifier string
// is a valid MAC for this plaintext under the currently loaded pepper.
// Constant-time comparison.
func VerifyVerifier(plain, verifier string) (bool, error) {
	want, err := Verifier(plain)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(verifier)) == 1, nil
}

// Backfill writes the new key_verifier column for a key that was
// originally stored with only the legacy SHA-256 key_hash. Called
// opportunistically from Resolve on the legacy code path so the next
// login uses the HMAC path.
//
// Runs in a best-effort background goroutine in the caller; the
// returned error only surfaces for tests.
func Backfill(ctx context.Context, pool apikeysExecer, keyID, verifier string, version int) error {
	_, err := pool.Exec(ctx,
		`UPDATE core.api_keys
		    SET key_verifier = $1, pepper_version = $2
		  WHERE id = $3 AND key_verifier IS NULL`,
		verifier, version, keyID)
	return err
}

// apikeysExecer is the subset of *pgxpool.Pool the backfill needs.
// Declaring it here avoids pulling in the pool type at this layer.
type apikeysExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (any, error)
}
