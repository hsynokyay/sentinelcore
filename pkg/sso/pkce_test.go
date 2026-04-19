package sso

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateVerifier_LengthAndCharset(t *testing.T) {
	v, err := GenerateVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) < 43 || len(v) > 128 {
		t.Fatalf("verifier length %d out of range", len(v))
	}
	re := regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	if !re.MatchString(v) {
		t.Fatalf("verifier has illegal chars: %q", v)
	}
}

func TestGenerateVerifier_Unique(t *testing.T) {
	a, _ := GenerateVerifier()
	b, _ := GenerateVerifier()
	if a == b {
		t.Fatal("verifiers must differ (crypto/rand)")
	}
}

func TestChallengeS256_KnownVector(t *testing.T) {
	// RFC 7636 appendix B test vector.
	got := ChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got != want {
		t.Fatalf("challenge mismatch:\n got=%s\nwant=%s", got, want)
	}
	raw, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("challenge should decode to 32 bytes, got %d", len(raw))
	}
	if strings.ContainsAny(got, "=+/") {
		t.Fatalf("challenge must be URL-safe no padding: %q", got)
	}
}
