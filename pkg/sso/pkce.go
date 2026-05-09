// Package sso implements OpenID Connect single sign-on flows.
package sso

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateVerifier returns a RFC 7636-compliant PKCE code verifier:
// 64 bytes of crypto-random data, base64url-encoded (no padding).
// That produces 86 chars — well within the 43-128 allowed range.
// Fails closed if the OS random source fails.
func GenerateVerifier() (string, error) {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("sso: crypto/rand failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ChallengeS256 returns the PKCE code_challenge for a verifier under the
// S256 method: BASE64URL(SHA256(ASCII(verifier))), no padding.
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
