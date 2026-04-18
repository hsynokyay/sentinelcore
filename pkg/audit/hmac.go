package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HMACCompute returns the hex-encoded HMAC-SHA256 of canonical under key.
// The returned string is 64 chars (32 bytes) lowercase hex.
//
// Note: key material must be kept in Vault (or, in the transitional phase,
// in the process env via AUDIT_HMAC_KEY_B64). Never log or serialise it.
func HMACCompute(key []byte, canonical string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(canonical))
	return hex.EncodeToString(m.Sum(nil))
}

// HMACVerify returns true iff got equals HMACCompute(key, canonical).
// Uses crypto/subtle.ConstantTimeCompare to avoid timing side channels on
// the verifier's hot path (hourly check over millions of rows).
func HMACVerify(key []byte, canonical string, got string) bool {
	want := HMACCompute(key, canonical)
	if len(want) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
