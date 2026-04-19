package crypto

import (
	"context"
	"strings"
	"testing"
)

// stubResolver hands out a static key map keyed by "purpose:version".
type stubResolver struct{ m map[string][]byte }

func (s stubResolver) ResolveKey(_ context.Context, p Purpose, v int) ([]byte, error) {
	return s.m[string(p)+":"+itoa(v)], nil
}

func itoa(i int) string {
	buf := [4]byte{}
	n := 0
	if i == 0 {
		buf[0] = '0'
		n = 1
	}
	for i > 0 {
		buf[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	for a, b := 0, n-1; a < b; a, b = a+1, b-1 {
		buf[a], buf[b] = buf[b], buf[a]
	}
	return string(buf[:n])
}

func TestParseEnvelope_Rejects(t *testing.T) {
	bad := []string{
		"",
		"enc:abc",
		"enc:v:sso:xxxx",
		"enc:v0:sso:xxxx",
		"enc:v1:sso",
		"enc:v1:sso:!!!notbase64!!!",
	}
	for _, s := range bad {
		if _, _, _, err := parseEnvelope(s); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}

func TestParseEnvelope_Happy(t *testing.T) {
	// "hello" → envelope with v2, purpose sso, known base64 body
	body := "aGVsbG8=" // base64("hello"), not real ciphertext but format test only
	ver, p, blob, err := parseEnvelope("enc:v2:sso:" + body)
	if err != nil {
		t.Fatal(err)
	}
	if ver != 2 || p != PurposeSSO || string(blob) != "hello" {
		t.Errorf("got ver=%d p=%s blob=%q", ver, p, blob)
	}
}

func TestEnvelope_SealOpen_NoDB(t *testing.T) {
	// Seal/Open without going through Reload — exercises the in-memory
	// path by pre-populating the cache manually. This is the unit-test
	// entry point; DB-backed tests live in envelope_db_test.go.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	aead, err := NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	e := &Envelope{
		aeads:   map[Purpose]map[int]*AESGCM{PurposeSSO: {1: aead}},
		current: map[Purpose]int{PurposeSSO: 1},
	}
	env, err := e.Seal(PurposeSSO, []byte("secret-value"), []byte("bind-me"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(env, "enc:v1:sso:") {
		t.Errorf("unexpected prefix: %q", env)
	}
	pt, err := e.Open(env, []byte("bind-me"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "secret-value" {
		t.Errorf("roundtrip: got %q", pt)
	}
	// AAD mismatch must fail.
	if _, err := e.Open(env, []byte("wrong-aad")); err == nil {
		t.Error("expected AAD mismatch error")
	}
	// Unknown version.
	if _, err := e.Open("enc:v99:sso:AAAAAA==", nil); err != ErrUnknownKey {
		t.Errorf("want ErrUnknownKey, got %v", err)
	}
}

func TestEnvelope_SealWithoutCurrentKey(t *testing.T) {
	e := NewEnvelope(nil, stubResolver{})
	if _, err := e.Seal(PurposeSSO, []byte("x"), nil); err == nil {
		t.Error("expected error when no current key loaded")
	}
}
