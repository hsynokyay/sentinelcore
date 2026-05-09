package httpsec

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func signForTest(secret, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts))
	m.Write([]byte{'\n'})
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func mkReq(t *testing.T, secret string, ts time.Time, body []byte) *http.Request {
	t.Helper()
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	sig := signForTest(secret, tsStr, body)
	r := httptest.NewRequest("POST", "/hook", bytes.NewReader(body))
	r.Header.Set("X-SentinelCore-Timestamp", tsStr)
	r.Header.Set("X-SentinelCore-Signature", "sha256="+sig)
	return r
}

func TestWebhookVerifier_Happy(t *testing.T) {
	v := &WebhookVerifier{}
	body := []byte(`{"event":"scan.completed"}`)
	r := mkReq(t, "s3cr3t", time.Now(), body)
	got, err := v.VerifyRequest(r, "s3cr3t")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body mismatch: %s vs %s", got, body)
	}
}

func TestWebhookVerifier_Rejects(t *testing.T) {
	body := []byte(`{}`)
	v := &WebhookVerifier{ReplayWindow: 30 * time.Second}

	cases := []struct {
		name   string
		setup  func() *http.Request
		secret string
	}{
		{
			name: "missing signature",
			setup: func() *http.Request {
				r := mkReq(t, "s", time.Now(), body)
				r.Header.Del("X-SentinelCore-Signature")
				return r
			},
			secret: "s",
		},
		{
			name: "missing timestamp",
			setup: func() *http.Request {
				r := mkReq(t, "s", time.Now(), body)
				r.Header.Del("X-SentinelCore-Timestamp")
				return r
			},
			secret: "s",
		},
		{
			name: "stale timestamp",
			setup: func() *http.Request {
				return mkReq(t, "s", time.Now().Add(-10*time.Minute), body)
			},
			secret: "s",
		},
		{
			name: "wrong secret",
			setup: func() *http.Request {
				return mkReq(t, "other", time.Now(), body)
			},
			secret: "s",
		},
		{
			name: "mutated body",
			setup: func() *http.Request {
				r := mkReq(t, "s", time.Now(), body)
				// Replace body after signing — MAC no longer matches.
				r.Body = io.NopCloser(bytes.NewReader([]byte(`{"evil":true}`)))
				return r
			},
			secret: "s",
		},
		{
			name:  "empty secret",
			setup: func() *http.Request { return mkReq(t, "s", time.Now(), body) },
			secret: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.VerifyRequest(tc.setup(), tc.secret)
			if !errors.Is(err, ErrWebhookInvalid) {
				t.Errorf("want ErrWebhookInvalid, got %v", err)
			}
		})
	}
}

func TestWebhookVerifier_ReplayBlocked(t *testing.T) {
	// A captured (ts, sig, body) triple cannot be replayed unchanged
	// once the window expires.
	v := &WebhookVerifier{ReplayWindow: 1 * time.Second}
	body := []byte(`hello`)
	ts := time.Now().Add(-5 * time.Second)
	r := mkReq(t, "s", ts, body)

	_, err := v.VerifyRequest(r, "s")
	if err == nil {
		t.Fatal("expected rejection, got success")
	}
	if !errors.Is(err, ErrWebhookInvalid) {
		t.Fatalf("want ErrWebhookInvalid, got %v", err)
	}
	_ = fmt.Sprint
}
