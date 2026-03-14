package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEd25519_SignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	message := []byte("hello sentinelcore")
	sig := Ed25519Sign(priv, message)

	if !Ed25519Verify(pub, message, sig) {
		t.Error("valid signature should verify")
	}
}

func TestEd25519_TamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("hello sentinelcore")
	sig := Ed25519Sign(priv, message)

	// Tamper with signature
	sig[0] ^= 0xff

	if Ed25519Verify(pub, message, sig) {
		t.Error("tampered signature should not verify")
	}
}

func TestEd25519_WrongKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	message := []byte("hello sentinelcore")
	sig := Ed25519Sign(priv1, message)

	if Ed25519Verify(pub2, message, sig) {
		t.Error("wrong key should not verify")
	}
}

func TestEd25519_InvalidInputs(t *testing.T) {
	if Ed25519Verify(nil, []byte("msg"), []byte("sig")) {
		t.Error("nil public key should not verify")
	}
	if Ed25519Verify(make([]byte, ed25519.PublicKeySize), []byte("msg"), []byte("short")) {
		t.Error("short signature should not verify")
	}
}
