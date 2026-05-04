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
