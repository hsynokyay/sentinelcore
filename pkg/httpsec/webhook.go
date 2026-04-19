package httpsec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WebhookVerifier validates the HMAC-SHA256 signature + timestamp
// headers on inbound webhooks.
//
// Wire format (matches the outbound DispatchScanWebhooks format):
//
//   X-SentinelCore-Signature: sha256=<hex(hmac(secret, body))>
//   X-SentinelCore-Timestamp: <unix-seconds>
//
// Replay protection: reject if |now - timestamp| > ReplayWindow.
// Default window is 5 minutes, matching common upstream norms
// (GitHub = 5min, Stripe = 5min).
//
// A single secret is supplied per-endpoint; multi-tenant receivers
// resolve the secret from the URL path's tenant segment BEFORE
// calling VerifyRequest.
type WebhookVerifier struct {
	ReplayWindow   time.Duration // default 5 min
	SignatureHeader string        // default "X-SentinelCore-Signature"
	TimestampHeader string        // default "X-SentinelCore-Timestamp"
}

// ErrWebhookInvalid is the sentinel for any verification failure.
// Callers compare with errors.Is; specific reasons are in the
// wrapped error's message.
var ErrWebhookInvalid = errors.New("httpsec: webhook verification failed")

// VerifyRequest reads r.Body (fully), validates the signature and
// timestamp headers, and returns the body bytes on success. On
// failure returns ErrWebhookInvalid wrapped with the reason; the
// body is discarded.
//
// Responsibility of the caller: supply the per-endpoint secret;
// handle the returned body; respond with 401 on ErrWebhookInvalid.
func (v *WebhookVerifier) VerifyRequest(r *http.Request, secret string) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("%w: no secret configured", ErrWebhookInvalid)
	}
	window := v.ReplayWindow
	if window <= 0 {
		window = 5 * time.Minute
	}
	sigHdr := v.SignatureHeader
	if sigHdr == "" {
		sigHdr = "X-SentinelCore-Signature"
	}
	tsHdr := v.TimestampHeader
	if tsHdr == "" {
		tsHdr = "X-SentinelCore-Timestamp"
	}

	tsStr := r.Header.Get(tsHdr)
	if tsStr == "" {
		return nil, fmt.Errorf("%w: missing %s", ErrWebhookInvalid, tsHdr)
	}
	tsUnix, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed timestamp", ErrWebhookInvalid)
	}
	ts := time.Unix(tsUnix, 0)
	if drift := time.Since(ts); drift > window || drift < -window {
		return nil, fmt.Errorf("%w: timestamp outside ±%s window", ErrWebhookInvalid, window)
	}

	got := r.Header.Get(sigHdr)
	if got == "" {
		return nil, fmt.Errorf("%w: missing %s", ErrWebhookInvalid, sigHdr)
	}
	// Strip the "sha256=" prefix if present for compatibility with
	// the outbound format. Accept bare hex too.
	got = strings.TrimPrefix(got, "sha256=")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrWebhookInvalid, err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	// Bind the MAC to the timestamp so an attacker who captures a
	// valid (timestamp, signature, body) triple cannot replay it
	// with a FRESH timestamp. The signed input is: ts || "\n" || body.
	mac.Write([]byte(tsStr))
	mac.Write([]byte{'\n'})
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(want), []byte(got)) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrWebhookInvalid)
	}
	return body, nil
}
