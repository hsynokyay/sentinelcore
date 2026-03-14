package sc_nats

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignMessage computes HMAC-SHA256 of payload and returns hex-encoded signature.
func SignMessage(key []byte, payload []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyMessage verifies the HMAC-SHA256 signature of a payload.
func VerifyMessage(key []byte, payload []byte, signature string) bool {
	expected := SignMessage(key, payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}
