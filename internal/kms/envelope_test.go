package kms_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// TestEnvelope_RoundTrip encrypts and then decrypts data, verifying that the
// plaintext round-trips and that the ciphertext differs from the plaintext.
func TestEnvelope_RoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newTestLocalProvider()
	plaintext := []byte("sensitive-payload-for-envelope-test")
	aad := []byte("user-id:42")

	env, err := kms.EncryptEnvelope(ctx, p, "test-purpose", plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}

	if bytes.Equal(env.Ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}
	if len(env.WrappedDEK) == 0 {
		t.Fatal("WrappedDEK is empty")
	}
	if len(env.IV) != 12 {
		t.Fatalf("IV length = %d, want 12", len(env.IV))
	}

	got, err := kms.DecryptEnvelope(ctx, p, env, aad)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}
}

// TestEnvelope_AADMismatchFails verifies that decrypting with a different AAD
// than was used during encryption returns an error.
func TestEnvelope_AADMismatchFails(t *testing.T) {
	ctx := context.Background()
	p := newTestLocalProvider()
	plaintext := []byte("aad-test-payload")

	env, err := kms.EncryptEnvelope(ctx, p, "test-purpose", plaintext, []byte("aad-1"))
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}

	_, err = kms.DecryptEnvelope(ctx, p, env, []byte("aad-2"))
	if err == nil {
		t.Fatal("expected error when decrypting with mismatched AAD, got nil")
	}
}

// TestEnvelope_TamperedCiphertextFails flips a bit in the ciphertext and
// verifies that decryption returns an error.
func TestEnvelope_TamperedCiphertextFails(t *testing.T) {
	ctx := context.Background()
	p := newTestLocalProvider()
	plaintext := []byte("tamper-ciphertext-payload")
	aad := []byte("some-context")

	env, err := kms.EncryptEnvelope(ctx, p, "test-purpose", plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}

	// Flip a bit in the middle of the ciphertext.
	tampered := make([]byte, len(env.Ciphertext))
	copy(tampered, env.Ciphertext)
	tampered[len(tampered)/2] ^= 0xFF
	env.Ciphertext = tampered

	_, err = kms.DecryptEnvelope(ctx, p, env, aad)
	if err == nil {
		t.Fatal("expected error when decrypting tampered ciphertext, got nil")
	}
}

// TestEnvelope_TamperedWrappedDEKFails flips a bit in the wrapped DEK and
// verifies that decryption returns an error.
func TestEnvelope_TamperedWrappedDEKFails(t *testing.T) {
	ctx := context.Background()
	p := newTestLocalProvider()
	plaintext := []byte("tamper-dek-payload")
	aad := []byte("some-context")

	env, err := kms.EncryptEnvelope(ctx, p, "test-purpose", plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}

	// Flip a bit in the wrapped DEK.
	tampered := make([]byte, len(env.WrappedDEK))
	copy(tampered, env.WrappedDEK)
	tampered[len(tampered)/2] ^= 0xFF
	env.WrappedDEK = tampered

	_, err = kms.DecryptEnvelope(ctx, p, env, aad)
	if err == nil {
		t.Fatal("expected error when decrypting with tampered WrappedDEK, got nil")
	}
}
