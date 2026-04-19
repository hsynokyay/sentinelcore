package integration

// key_rotation_test.go — verifies the AES envelope reads old and new
// ciphertexts correctly across a rotation.
//
// The rotation drill:
//   1. Seed aes_keys v1 for purpose "generic".
//   2. Seal a plaintext under v1 → blob_v1.
//   3. Seed aes_keys v2.
//   4. Seal a fresh plaintext under v2 → blob_v2.
//   5. Reload envelope cache.
//   6. Open blob_v1 → must decrypt to the original plaintext.
//   7. Open blob_v2 → must decrypt to the second plaintext.
//
// Environment: TEST_DATABASE_URL; without it, skip.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/crypto"
)

// staticKeyResolver implements crypto.KeyResolver with an in-memory
// map for tests. Production uses a secrets.Resolver.
type staticKeyResolver struct {
	keys map[string][]byte // "purpose:version" → 32 bytes
}

func (s staticKeyResolver) ResolveKey(_ context.Context, p crypto.Purpose, v int) ([]byte, error) {
	return s.keys[string(p)+":"+itoa(v)], nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	buf := [8]byte{}
	n := 0
	for i > 0 {
		buf[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	for a, b := 0, n-1; a < b; a, b = a+1, b-1 {
		buf[a], buf[b] = buf[b], buf[a]
	}
	return string(buf[:n])
}

func TestKeyRotation_EnvelopeReadsBothVersions(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	ctx := context.Background()

	// Fresh purpose unique per run so we don't collide with other
	// parallel tests. Using "generic" + a random suffix violates the
	// CHECK; use a stable "generic" and clean up old rows first.
	const purpose = "generic"
	_, _ = pool.Exec(ctx,
		`DELETE FROM auth.aes_keys WHERE purpose = $1`, purpose)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx,
			`DELETE FROM auth.aes_keys WHERE purpose = $1`, purpose)
	})

	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)

	fp1 := sha256Hex(key1)
	fp2 := sha256Hex(key2)

	insertKey := func(ver int, fp string) {
		t.Helper()
		_, err := pool.Exec(ctx,
			`INSERT INTO auth.aes_keys (version, purpose, vault_path, fingerprint)
			 VALUES ($1, $2, $3, $4)`,
			ver, purpose, "env:TEST_V"+itoa(ver), fp)
		if err != nil {
			t.Fatalf("insert aes_keys v%d: %v", ver, err)
		}
	}

	// --- Phase 1: only v1 exists ---
	insertKey(1, fp1)

	resolver := staticKeyResolver{keys: map[string][]byte{
		purpose + ":1": key1,
	}}
	env := crypto.NewEnvelope(pool, resolver)
	if err := env.Reload(ctx); err != nil {
		t.Fatalf("reload v1: %v", err)
	}

	plain1 := []byte("pre-rotation payload")
	blob1, err := env.Seal(crypto.Purpose(purpose), plain1, nil)
	if err != nil {
		t.Fatalf("seal v1: %v", err)
	}

	// --- Phase 2: v2 arrives ---
	insertKey(2, fp2)
	resolver.keys[purpose+":2"] = key2
	if err := env.Reload(ctx); err != nil {
		t.Fatalf("reload v2: %v", err)
	}

	plain2 := []byte("post-rotation payload")
	blob2, err := env.Seal(crypto.Purpose(purpose), plain2, nil)
	if err != nil {
		t.Fatalf("seal v2: %v", err)
	}

	// --- Verify Seal picked the NEW version ---
	if got := env.CurrentVersion(crypto.Purpose(purpose)); got != 2 {
		t.Errorf("CurrentVersion after Reload: got %d, want 2", got)
	}

	// --- Verify Open decrypts BOTH versions ---
	got1, err := env.Open(blob1, nil)
	if err != nil || string(got1) != string(plain1) {
		t.Errorf("v1 open: got %q err %v", got1, err)
	}
	got2, err := env.Open(blob2, nil)
	if err != nil || string(got2) != string(plain2) {
		t.Errorf("v2 open: got %q err %v", got2, err)
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
