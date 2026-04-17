package aesgcm

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	e, err := NewEncryptor(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, pt := range []string{"", "a", "my client secret", strings.Repeat("x", 1024)} {
		ct, err := e.Encrypt(pt)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if !strings.HasPrefix(ct, "enc:v1:") {
			t.Errorf("missing prefix: %q", ct)
		}
		got, err := e.Decrypt(ct)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != pt {
			t.Errorf("roundtrip: got %q want %q", got, pt)
		}
	}
}

func TestNonceUnique(t *testing.T) {
	e, _ := NewEncryptor(mustKey(t))
	a, _ := e.Encrypt("same")
	b, _ := e.Encrypt("same")
	if a == b {
		t.Fatal("same plaintext must produce different ciphertexts (fresh nonce)")
	}
}

func TestDecrypt_Tampered(t *testing.T) {
	e, _ := NewEncryptor(mustKey(t))
	ct, _ := e.Encrypt("secret")
	// Flip last char in base64 section.
	bad := []byte(ct)
	bad[len(bad)-1] ^= 0x01
	if _, err := e.Decrypt(string(bad)); err == nil {
		t.Fatal("tampered ciphertext must fail to decrypt")
	}
}

func TestDecrypt_BadPrefix(t *testing.T) {
	e, _ := NewEncryptor(mustKey(t))
	if _, err := e.Decrypt("plaintext"); err == nil {
		t.Fatal("ciphertext without prefix must fail")
	}
	if _, err := e.Decrypt("enc:v2:abc"); err == nil {
		t.Fatal("wrong version prefix must fail")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	e1, _ := NewEncryptor(mustKey(t))
	e2, _ := NewEncryptor(mustKey(t))
	ct, _ := e1.Encrypt("secret")
	if _, err := e2.Decrypt(ct); err == nil {
		t.Fatal("decrypt with different key must fail")
	}
}

func TestNewEncryptor_BadKeyLen(t *testing.T) {
	if _, err := NewEncryptor(bytes.Repeat([]byte{1}, 16)); err == nil {
		t.Fatal("16-byte key must be rejected")
	}
	if _, err := NewEncryptor(nil); err == nil {
		t.Fatal("nil key must be rejected")
	}
}
