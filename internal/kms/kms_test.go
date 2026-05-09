package kms_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// stubProvider satisfies the Provider interface for testing the registry.
type stubProvider struct {
	name string
}

func (s *stubProvider) Name() string { return s.name }

func (s *stubProvider) GenerateDataKey(_ context.Context, _ string) (kms.DataKey, error) {
	return kms.DataKey{}, errors.New("not implemented")
}

func (s *stubProvider) Decrypt(_ context.Context, _ []byte, _ string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *stubProvider) HMAC(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *stubProvider) HMACVerify(_ context.Context, _ string, _ []byte, _ []byte) (bool, error) {
	return false, errors.New("not implemented")
}

// TestDataKey_Zeroize verifies that Zeroize overwrites the Plaintext slice.
func TestDataKey_Zeroize(t *testing.T) {
	dk := kms.DataKey{
		Plaintext:  []byte{0x01, 0x02, 0x03, 0x04},
		Wrapped:    []byte{0xFF},
		KeyVersion: "v1",
	}
	dk.Zeroize()
	for i, b := range dk.Plaintext {
		if b != 0 {
			t.Fatalf("Plaintext[%d] = %d, want 0 after Zeroize", i, b)
		}
	}
}

// TestRegistry_RegisterAndGet registers a stub provider and retrieves it.
func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := kms.NewRegistry()
	stub := &stubProvider{name: "test-provider"}
	reg.Register(stub)

	got, err := reg.Get("test-provider")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.Name() != "test-provider" {
		t.Fatalf("got.Name() = %q, want %q", got.Name(), "test-provider")
	}
}

// TestRegistry_GetUnknown verifies that getting a nonexistent provider returns
// ErrUnknownProvider.
func TestRegistry_GetUnknown(t *testing.T) {
	reg := kms.NewRegistry()
	_, err := reg.Get("no-such-provider")
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
	if !errors.Is(err, kms.ErrUnknownProvider) {
		t.Fatalf("err = %v, want errors.Is(err, ErrUnknownProvider) == true", err)
	}
}

// newTestLocalProvider returns a LocalProvider with a fixed 32-byte master key
// for deterministic tests.
func newTestLocalProvider() *kms.LocalProvider {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	return kms.NewLocalProvider(master)
}

// TestLocalProvider_RoundTrip generates a DEK, decrypts it, verifies equality,
// then Zeroizes and confirms the plaintext is cleared.
func TestLocalProvider_RoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newTestLocalProvider()

	dk, err := p.GenerateDataKey(ctx, "test-purpose")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}

	// Save a copy of plaintext before decryption for comparison.
	original := make([]byte, len(dk.Plaintext))
	copy(original, dk.Plaintext)

	decrypted, err := p.Decrypt(ctx, dk.Wrapped, dk.KeyVersion)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(decrypted) != len(original) {
		t.Fatalf("decrypted len = %d, want %d", len(decrypted), len(original))
	}
	for i := range original {
		if decrypted[i] != original[i] {
			t.Fatalf("decrypted[%d] = %x, want %x", i, decrypted[i], original[i])
		}
	}

	// Zeroize and verify plaintext is cleared.
	dk.Zeroize()
	for i, b := range dk.Plaintext {
		if b != 0 {
			t.Fatalf("Plaintext[%d] = %d after Zeroize, want 0", i, b)
		}
	}
}

// TestLocalProvider_TamperedWrappedKeyFails flips a bit in the wrapped key and
// verifies that Decrypt returns an error.
func TestLocalProvider_TamperedWrappedKeyFails(t *testing.T) {
	ctx := context.Background()
	p := newTestLocalProvider()

	dk, err := p.GenerateDataKey(ctx, "tamper-test")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}

	// Flip a bit in the middle of the wrapped key.
	tampered := make([]byte, len(dk.Wrapped))
	copy(tampered, dk.Wrapped)
	tampered[len(tampered)/2] ^= 0xFF

	_, err = p.Decrypt(ctx, tampered, dk.KeyVersion)
	if err == nil {
		t.Fatal("expected error decrypting tampered wrapped key, got nil")
	}
}

// TestLocalProvider_HMAC verifies HMAC computation, successful verification,
// and detection of a tampered MAC.
func TestLocalProvider_HMAC(t *testing.T) {
	ctx := context.Background()
	p := newTestLocalProvider()
	msg := []byte("hello, sentinel")

	mac, err := p.HMAC(ctx, "auth/signing-key", msg)
	if err != nil {
		t.Fatalf("HMAC: %v", err)
	}
	if len(mac) == 0 {
		t.Fatal("HMAC returned empty MAC")
	}

	// Verify the correct MAC.
	ok, err := p.HMACVerify(ctx, "auth/signing-key", msg, mac)
	if err != nil {
		t.Fatalf("HMACVerify: %v", err)
	}
	if !ok {
		t.Fatal("HMACVerify returned false for a valid MAC")
	}

	// Tamper with the MAC and verify it fails.
	tampered := make([]byte, len(mac))
	copy(tampered, mac)
	tampered[0] ^= 0xFF

	ok, err = p.HMACVerify(ctx, "auth/signing-key", msg, tampered)
	if err != nil {
		t.Fatalf("HMACVerify (tampered): %v", err)
	}
	if ok {
		t.Fatal("HMACVerify returned true for a tampered MAC")
	}
}
