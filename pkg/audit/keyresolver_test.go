package audit

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestEnvKeyResolver_Happy(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	r, err := NewEnvKeyResolverFromBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Key(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("wrong key length: %d", len(got))
	}
	if r.CurrentVersion() != 1 {
		t.Errorf("CurrentVersion() = %d, want 1", r.CurrentVersion())
	}
	// Fingerprint is 64 hex chars.
	fp := r.Fingerprint()
	if len(fp) != 64 {
		t.Errorf("fingerprint length: got %d want 64", len(fp))
	}
}

func TestEnvKeyResolver_EmptyEnv(t *testing.T) {
	_, err := NewEnvKeyResolverFromBase64("")
	if !errors.Is(err, ErrKeyMissing) {
		t.Errorf("want ErrKeyMissing, got %v", err)
	}
}

func TestEnvKeyResolver_BadBase64(t *testing.T) {
	_, err := NewEnvKeyResolverFromBase64("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error on invalid base64")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error missing 'base64': %v", err)
	}
}

func TestEnvKeyResolver_WrongLength(t *testing.T) {
	// 16-byte key (128-bit) — encoded to base64 and handed to the resolver.
	short := base64.StdEncoding.EncodeToString([]byte("exactly16bytes..."))
	_, err := NewEnvKeyResolverFromBase64(short)
	if err == nil {
		t.Fatal("expected error for non-32-byte key")
	}
}

func TestEnvKeyResolver_UnknownVersion(t *testing.T) {
	raw := make([]byte, 32)
	b64 := base64.StdEncoding.EncodeToString(raw)
	r, _ := NewEnvKeyResolverFromBase64(b64)
	if _, err := r.Key(2); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("want ErrKeyMissing for v2, got %v", err)
	}
}
