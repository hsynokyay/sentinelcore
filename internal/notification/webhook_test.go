package notification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid HTTPS URL",
			url:     "https://example.com/webhook",
			wantErr: false,
		},
		{
			name:    "HTTP rejected for non-localhost",
			url:     "http://example.com/webhook",
			wantErr: true,
		},
		{
			name:    "HTTP allowed for localhost",
			url:     "http://localhost:8080/webhook",
			wantErr: false,
		},
		{
			name:    "HTTP allowed for 127.0.0.1",
			url:     "http://127.0.0.1:9000/hook",
			wantErr: false,
		},
		{
			name:    "reject private IP 10.x",
			url:     "https://10.0.0.1/hook",
			wantErr: true,
		},
		{
			name:    "reject private IP 172.16.x",
			url:     "https://172.16.0.1/hook",
			wantErr: true,
		},
		{
			name:    "reject private IP 192.168.x",
			url:     "https://192.168.1.1/hook",
			wantErr: true,
		},
		{
			name:    "reject URL with userinfo",
			url:     "https://user:pass@example.com/hook",
			wantErr: true,
		},
		{
			name:    "reject unsupported scheme",
			url:     "ftp://example.com/hook",
			wantErr: true,
		},
		{
			name:    "localhost resolves to blocked 127.0.0.1 for HTTPS",
			url:     "https://localhost/hook",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWebhookURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestSignPayload(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	secret := []byte("mysecret")

	sig := SignPayload(payload, secret)

	// Verify it's a valid hex string of expected length (SHA-256 = 64 hex chars).
	if len(sig) != 64 {
		t.Fatalf("expected 64 hex chars, got %d: %s", len(sig), sig)
	}

	// Verify deterministic output.
	sig2 := SignPayload(payload, secret)
	if sig != sig2 {
		t.Fatalf("signatures differ: %s vs %s", sig, sig2)
	}

	// Different secret should produce different signature.
	sig3 := SignPayload(payload, []byte("other"))
	if sig == sig3 {
		t.Fatal("different secrets should produce different signatures")
	}
}

func TestVerifySignature(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	secret := []byte("mysecret")

	sig := SignPayload(payload, secret)

	if !VerifySignature(payload, secret, sig) {
		t.Fatal("expected valid signature to verify")
	}

	if VerifySignature(payload, secret, "invalid") {
		t.Fatal("expected invalid signature to fail verification")
	}

	if VerifySignature(payload, []byte("wrong"), sig) {
		t.Fatal("expected wrong secret to fail verification")
	}
}

func TestDeliverWebhook(t *testing.T) {
	var (
		gotBody      []byte
		gotSigHeader string
		gotEvtHeader string
		gotCType     string
	)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSigHeader = r.Header.Get("X-Sentinel-Signature")
		gotEvtHeader = r.Header.Get("X-Sentinel-Event")
		gotCType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// Override package-level variables for testing.
	origValidate := validateURL
	origClient := httpClient
	validateURL = func(_ string) error { return nil } // skip SSRF check for test server
	httpClient = srv.Client()
	defer func() {
		validateURL = origValidate
		httpClient = origClient
	}()

	secret := []byte("webhook-secret")
	payload := json.RawMessage(`{"finding_id":"f-123","severity":"high"}`)

	config := &WebhookConfig{
		ID:   "wh-1",
		Name: "test-hook",
		URL:  srv.URL + "/webhook",
	}

	attempt, err := DeliverWebhook(context.Background(), config, "finding.created", payload, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status.
	if attempt.Status != "delivered" {
		t.Errorf("expected status 'delivered', got %q", attempt.Status)
	}

	// Verify response code.
	if attempt.ResponseCode != http.StatusOK {
		t.Errorf("expected response code 200, got %d", attempt.ResponseCode)
	}

	// Verify payload was sent correctly.
	if string(gotBody) != string(payload) {
		t.Errorf("payload mismatch: got %q, want %q", gotBody, payload)
	}

	// Verify Content-Type header.
	if gotCType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCType)
	}

	// Verify event header.
	if gotEvtHeader != "finding.created" {
		t.Errorf("X-Sentinel-Event = %q, want finding.created", gotEvtHeader)
	}

	// Verify signature header.
	expectedSig := "sha256=" + SignPayload(payload, secret)
	if gotSigHeader != expectedSig {
		t.Errorf("X-Sentinel-Signature = %q, want %q", gotSigHeader, expectedSig)
	}

	// Verify webhook ID on attempt.
	if attempt.WebhookID != "wh-1" {
		t.Errorf("attempt.WebhookID = %q, want wh-1", attempt.WebhookID)
	}
}

func TestDeliverWebhook_FailedStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer srv.Close()

	origValidate := validateURL
	origClient := httpClient
	validateURL = func(_ string) error { return nil }
	httpClient = srv.Client()
	defer func() {
		validateURL = origValidate
		httpClient = origClient
	}()

	config := &WebhookConfig{
		ID:  "wh-2",
		URL: srv.URL + "/hook",
	}

	attempt, err := DeliverWebhook(context.Background(), config, "test.event",
		json.RawMessage(`{}`), []byte("s"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempt.Status != "failed" {
		t.Errorf("expected status 'failed', got %q", attempt.Status)
	}
	if attempt.ResponseCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", attempt.ResponseCode)
	}
}

func TestDeliverWebhook_NilConfig(t *testing.T) {
	_, err := DeliverWebhook(context.Background(), nil, "evt", json.RawMessage(`{}`), []byte("s"))
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}
