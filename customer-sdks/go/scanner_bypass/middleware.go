// Package scanner_bypass provides reference middleware for SentinelCore
// scanner bypass tokens. Use this in your test/staging environment to
// recognize verified scanner traffic and skip protections such as CAPTCHA,
// rate limiting, or MFA.
//
// SECURITY: deploy this middleware ONLY in environments where you have
// explicit authorization to bypass production protections. Do NOT enable
// in production. The HMAC secret must be obtained from your SentinelCore
// administrator and stored in a secret manager (Vault, AWS Secrets
// Manager, Azure Key Vault) — never in source control.
package scanner_bypass

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const HeaderName = "X-Sentinelcore-Scanner-Token"

type Verified struct {
	ScanJobID string
	IssuedAt  time.Time
	Nonce     string
}

type Verifier struct {
	secret    []byte
	now       func() time.Time
	nonceMu   sync.Mutex
	nonceSeen map[string]time.Time
}

func NewVerifier(secret []byte, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		secret:    secret,
		now:       now,
		nonceSeen: make(map[string]time.Time),
	}
}

func (v *Verifier) Verify(token, host string) (*Verified, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[0] != "v1" {
		return nil, errors.New("invalid token format")
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse ts: %w", err)
	}
	scanJobID := parts[2]
	nonce := parts[3]
	mac, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("decode mac: %w", err)
	}

	issuedAt := time.Unix(ts, 0).UTC()
	now := v.now().UTC()
	if now.Sub(issuedAt) > 5*time.Minute || issuedAt.Sub(now) > 30*time.Second {
		return nil, errors.New("token outside time window")
	}

	v.nonceMu.Lock()
	defer v.nonceMu.Unlock()
	if _, seen := v.nonceSeen[nonce]; seen {
		return nil, errors.New("nonce replay")
	}
	for k, t := range v.nonceSeen {
		if now.Sub(t) > 10*time.Minute {
			delete(v.nonceSeen, k)
		}
	}

	msg := fmt.Sprintf("v1|%s|%s|%s|%s", parts[1], scanJobID, nonce, host)
	expected := hmacSHA256(v.secret, []byte(msg))
	if !hmac.Equal(expected, mac) {
		return nil, errors.New("hmac mismatch")
	}
	v.nonceSeen[nonce] = now
	return &Verified{ScanJobID: scanJobID, IssuedAt: issuedAt, Nonce: nonce}, nil
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

type ctxKey struct{}

func FromContext(ctx context.Context) (*Verified, bool) {
	v, ok := ctx.Value(ctxKey{}).(*Verified)
	return v, ok
}

func Middleware(secret []byte) func(http.Handler) http.Handler {
	verifier := NewVerifier(secret, nil)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := r.Header.Get(HeaderName)
			if tok == "" {
				next.ServeHTTP(w, r)
				return
			}
			ver, err := verifier.Verify(tok, r.Host)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, ver)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func IsTrustedScanner(r *http.Request) bool {
	_, ok := FromContext(r.Context())
	return ok
}
