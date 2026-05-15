package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIdP is a minimal OIDC discovery + JWKS + signing fixture.
// It is NOT a full IdP — no /authorize or /token endpoints beyond
// what the verify path needs. Exchange tests, when added, can extend
// this by registering a /token handler.
type fakeIdP struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	keyID     string
	algOverride string // if set, override the JWS alg header (for tamper tests)

	signingKey *rsa.PrivateKey // defaults to key; can be swapped to simulate rotation / tamper
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	f := &fakeIdP{
		key:        priv,
		keyID:      "test-kid-1",
		signingKey: priv,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) issuer() string { return f.srv.URL }

func (f *fakeIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"issuer":                   f.issuer(),
		"authorization_endpoint":   f.issuer() + "/authorize",
		"token_endpoint":           f.issuer() + "/token",
		"jwks_uri":                 f.issuer() + "/jwks",
		"end_session_endpoint":     f.issuer() + "/logout",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(f.key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(bigEndianBytes(f.key.E))
	resp := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": f.keyID,
				"n":   n,
				"e":   e,
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// signToken issues an id_token signed with f.signingKey. Caller supplies
// the full claim map; helper fills missing iss/iat defaults.
func (f *fakeIdP) signToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = f.issuer()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.keyID
	if f.algOverride != "" {
		tok.Header["alg"] = f.algOverride
	}
	s, err := tok.SignedString(f.signingKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// tamperSignature flips one byte in the last segment of the JWT so the
// signature no longer validates.
func tamperSignature(tok string) string {
	segs := strings.Split(tok, ".")
	if len(segs) != 3 {
		return tok
	}
	sig, err := base64.RawURLEncoding.DecodeString(segs[2])
	if err != nil || len(sig) == 0 {
		return tok
	}
	sig[0] ^= 0x01
	segs[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(segs, ".")
}

// bigEndianBytes marshals E correctly for JWK (variable length).
func bigEndianBytes(e int) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(e))
	for i, b := range buf {
		if b != 0 {
			return buf[i:]
		}
	}
	return []byte{0}
}

// Silence unused imports during iteration: these are used in peer tests.
var (
	_ = sha256.Sum256
	_ = new(big.Int)
	_ = fmt.Sprintf
)
