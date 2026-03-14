package sc_nats

import (
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	key := []byte("test-secret-key")
	payload := []byte(`{"scan_id":"123","result":"clean"}`)

	sig := SignMessage(key, payload)
	if sig == "" {
		t.Fatal("signature should not be empty")
	}

	if !VerifyMessage(key, payload, sig) {
		t.Error("valid signature should verify")
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	key := []byte("test-secret-key")
	payload := []byte(`{"scan_id":"123","result":"clean"}`)
	sig := SignMessage(key, payload)

	tampered := []byte(`{"scan_id":"123","result":"malware"}`)
	if VerifyMessage(key, tampered, sig) {
		t.Error("tampered payload should not verify")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	key := []byte("test-secret-key")
	payload := []byte(`{"scan_id":"123","result":"clean"}`)
	sig := SignMessage(key, payload)

	wrongKey := []byte("wrong-key")
	if VerifyMessage(wrongKey, payload, sig) {
		t.Error("wrong key should not verify")
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	key := []byte("test-secret-key")
	payload := []byte("hello")

	if VerifyMessage(key, payload, "invalid-hex") {
		t.Error("invalid signature should not verify")
	}
}
