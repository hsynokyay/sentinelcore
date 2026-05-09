package scanner_bypass

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func issueToken(secret []byte, scanJobID, host string, when time.Time, nonce string) string {
	ts := fmt.Sprintf("%d", when.Unix())
	msg := fmt.Sprintf("v1|%s|%s|%s|%s", ts, scanJobID, nonce, host)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	mac := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("v1.%s.%s.%s.%s", ts, scanJobID, nonce, mac)
}

func TestMiddleware_Trusts(t *testing.T) {
	secret := []byte("test-secret")
	tok := issueToken(secret, "scan-1", "example.com", time.Now(), "nonce-1")
	handler := Middleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsTrustedScanner(r) {
			t.Error("expected trusted scanner")
		}
	}))
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Host = "example.com"
	req.Header.Set(HeaderName, tok)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

func TestMiddleware_RejectsWrongHost(t *testing.T) {
	secret := []byte("test-secret")
	tok := issueToken(secret, "scan-1", "example.com", time.Now(), "nonce-1")
	handler := Middleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsTrustedScanner(r) {
			t.Error("should not trust scanner with wrong host")
		}
	}))
	req := httptest.NewRequest("GET", "http://other.com/", nil)
	req.Host = "other.com"
	req.Header.Set(HeaderName, tok)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}
