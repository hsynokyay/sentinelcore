package apikeys

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifier_NoPepper(t *testing.T) {
	// Reset state.
	pepperBytes = nil
	pepperVersion = 0
	if _, err := Verifier("sc_abcdef"); err != ErrPepperMissing {
		t.Errorf("want ErrPepperMissing, got %v", err)
	}
}

func TestLoadPepper_Validates(t *testing.T) {
	// Version bounds.
	t.Setenv("SC_APIKEY_PEPPER_B64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err := LoadPepper(0); err == nil {
		t.Error("expected error for version=0")
	}
	// Too-short pepper.
	t.Setenv("SC_APIKEY_PEPPER_B64", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if err := LoadPepper(1); err == nil {
		t.Error("expected error for short pepper")
	}
}

func TestVerifier_RoundTrip(t *testing.T) {
	t.Setenv("SC_APIKEY_PEPPER_B64",
		base64.StdEncoding.EncodeToString([]byte("this-is-a-32-byte-test-pepper!!!")))
	if err := LoadPepper(1); err != nil {
		t.Fatal(err)
	}
	key := "sc_" + strings.Repeat("a", 32)
	v1, err := Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v1, "v1:") {
		t.Errorf("want v1 prefix, got %q", v1)
	}
	// Same key, same pepper ⇒ same verifier (deterministic).
	v2, err := Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 {
		t.Errorf("non-deterministic: %q vs %q", v1, v2)
	}
	// Different key ⇒ different verifier.
	v3, _ := Verifier(key + "different")
	if v1 == v3 {
		t.Error("different keys produced same verifier")
	}
	// Verify round-trip matches.
	if ok, err := VerifyVerifier(key, v1); err != nil || !ok {
		t.Errorf("VerifyVerifier: ok=%v err=%v", ok, err)
	}
	// Verify tampered MAC fails.
	tampered := v1[:len(v1)-4] + "AAAA"
	if ok, _ := VerifyVerifier(key, tampered); ok {
		t.Error("tampered MAC accepted")
	}
}

func TestVerifier_VersionBinding(t *testing.T) {
	// v1 pepper produces a MAC that shouldn't verify under v2.
	t.Setenv("SC_APIKEY_PEPPER_B64",
		base64.StdEncoding.EncodeToString([]byte("zzzzzzzz-pepper-thirty-two-bytes")))
	if err := LoadPepper(1); err != nil {
		t.Fatal(err)
	}
	key := "sc_" + strings.Repeat("b", 32)
	v1, _ := Verifier(key)

	// Rotate to v2 with same bytes. The version is baked into the MAC
	// input, so v2 produces a different MAC.
	if err := LoadPepper(2); err != nil {
		t.Fatal(err)
	}
	v2, _ := Verifier(key)
	if v1 == v2 {
		t.Error("v1 and v2 produced identical MAC — version binding broken")
	}
	if !strings.HasPrefix(v2, "v2:") {
		t.Errorf("want v2 prefix, got %q", v2)
	}
}
