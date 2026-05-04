package dast

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// BypassTokenHeader is the HTTP header name used to carry the scanner bypass token.
const BypassTokenHeader = "X-Sentinelcore-Scanner-Token"

// BypassTokenIssuer issues and verifies scanner bypass tokens.
// Tokens bind a scan job to a target host and are valid for a 5-minute window.
// Nonce replay protection prevents re-use of the same token within 10 minutes.
type BypassTokenIssuer struct {
	kms       kms.Provider
	keyPath   string
	now       func() time.Time
	nonceMu   sync.Mutex
	nonceSeen map[string]time.Time
}

// NewBypassTokenIssuer creates a BypassTokenIssuer backed by the given KMS provider.
// keyPath identifies the HMAC key within the provider. now is the clock function;
// pass time.Now for production use.
func NewBypassTokenIssuer(k kms.Provider, keyPath string, now func() time.Time) *BypassTokenIssuer {
	return &BypassTokenIssuer{
		kms:       k,
		keyPath:   keyPath,
		now:       now,
		nonceSeen: make(map[string]time.Time),
	}
}

// Verified is the result of a successful token verification.
type Verified struct {
	ScanJobID string
	IssuedAt  time.Time
	Nonce     string
}

// Issue mints a new bypass token for the given scan job and target host.
// Token format: v1.{ts}.{scan_job_id}.{nonce}.{hmac-b64url}
func (i *BypassTokenIssuer) Issue(ctx context.Context, scanJobID, targetHost string) (string, error) {
	ts := strconv.FormatInt(i.now().Unix(), 10)

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("bypass: rand: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	msg := fmt.Sprintf("v1|%s|%s|%s|%s", ts, scanJobID, nonce, targetHost)
	mac, err := i.kms.HMAC(ctx, i.keyPath, []byte(msg))
	if err != nil {
		return "", fmt.Errorf("bypass: hmac: %w", err)
	}

	return fmt.Sprintf("v1.%s.%s.%s.%s",
		ts, scanJobID, nonce,
		base64.RawURLEncoding.EncodeToString(mac),
	), nil
}

// Verify validates a bypass token against the given target host.
// It enforces a 5-minute forward window (with 30s clock skew allowance),
// nonce uniqueness, and HMAC integrity.
func (i *BypassTokenIssuer) Verify(ctx context.Context, token, targetHost string) (*Verified, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[0] != "v1" {
		return nil, fmt.Errorf("bypass: invalid format")
	}

	tsInt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bypass: invalid format")
	}
	scanJobID := parts[2]
	nonce := parts[3]

	mac, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("bypass: invalid format")
	}

	issuedAt := time.Unix(tsInt, 0).UTC()
	now := i.now().UTC()

	// Time window: issued at most 5 minutes ago, and not more than 30s in the future.
	if now.Sub(issuedAt) > 5*time.Minute || issuedAt.Sub(now) > 30*time.Second {
		return nil, fmt.Errorf("bypass: token outside time window")
	}

	// Nonce replay check (hold lock for the rest of the verification).
	i.nonceMu.Lock()
	defer i.nonceMu.Unlock()

	if _, seen := i.nonceSeen[nonce]; seen {
		return nil, fmt.Errorf("bypass: nonce replay")
	}

	// Trim stale nonce entries.
	for k, t := range i.nonceSeen {
		if now.Sub(t) > 10*time.Minute {
			delete(i.nonceSeen, k)
		}
	}

	// HMAC verification.
	msg := fmt.Sprintf("v1|%s|%s|%s|%s", parts[1], scanJobID, nonce, targetHost)
	ok, err := i.kms.HMACVerify(ctx, i.keyPath, []byte(msg), mac)
	if err != nil {
		return nil, fmt.Errorf("bypass: hmac: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("bypass: hmac mismatch")
	}

	// Record nonce only after all checks pass.
	i.nonceSeen[nonce] = now

	return &Verified{
		ScanJobID: scanJobID,
		IssuedAt:  issuedAt,
		Nonce:     nonce,
	}, nil
}
