package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func testKey() []byte {
	k, _ := hex.DecodeString("258475aa308620d4b3702953dfc25f880ec7d66cfa01c5fcd5efcf1066df2f2a")
	return k
}

func TestAESGCMRoundtrip(t *testing.T) {
	a, err := NewAESGCM(testKey())
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("correct horse battery staple")
	aad := []byte("project-id:abc")

	blob, err := a.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("ciphertext leaked plaintext")
	}

	got, err := a.Open(blob, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: %q vs %q", got, plaintext)
	}
}

func TestAESGCMWrongAAD(t *testing.T) {
	a, _ := NewAESGCM(testKey())
	blob, _ := a.Seal([]byte("secret"), []byte("aad-1"))
	if _, err := a.Open(blob, []byte("aad-2")); err == nil {
		t.Fatal("expected auth failure with wrong AAD")
	}
}

func TestAESGCMTamperedCiphertext(t *testing.T) {
	a, _ := NewAESGCM(testKey())
	blob, _ := a.Seal([]byte("secret"), nil)
	blob[len(blob)-1] ^= 0xff
	if _, err := a.Open(blob, nil); err == nil {
		t.Fatal("expected auth failure on tampered ciphertext")
	}
}

func TestAESGCMUniqueNonces(t *testing.T) {
	a, _ := NewAESGCM(testKey())
	b1, _ := a.Seal([]byte("same"), nil)
	b2, _ := a.Seal([]byte("same"), nil)
	if bytes.Equal(b1, b2) {
		t.Fatal("identical plaintexts must produce different ciphertexts")
	}
}

func TestAESGCMInvalidKeyLength(t *testing.T) {
	if _, err := NewAESGCM([]byte("short")); err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestDecodeHexKey(t *testing.T) {
	k, err := DecodeHexKey("258475aa308620d4b3702953dfc25f880ec7d66cfa01c5fcd5efcf1066df2f2a")
	if err != nil || len(k) != 32 {
		t.Fatalf("valid 64-hex key: got len=%d err=%v", len(k), err)
	}
	if _, err := DecodeHexKey("too-short"); err == nil {
		t.Fatal("expected error on short key")
	}
	if _, err := DecodeHexKey(strings.Repeat("z", 64)); err == nil {
		t.Fatal("expected error on non-hex")
	}
}
