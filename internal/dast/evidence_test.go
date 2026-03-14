package dast

import (
	"net/http"
	"strings"
	"testing"
)

func TestRedactBody(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string // should NOT contain the original sensitive value
	}{
		{
			name:   "password field",
			input:  `{"password": "secret123"}`,
			expect: "secret123",
		},
		{
			name:   "bearer token",
			input:  `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9`,
			expect: "eyJhbGciOiJIUzI1NiJ9",
		},
		{
			name:   "api_key field",
			input:  `api_key=sk-live-123456`,
			expect: "sk-live-123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactBody(tt.input)
			if strings.Contains(result, tt.expect) {
				t.Errorf("expected %q to be redacted from output: %s", tt.expect, result)
			}
		})
	}
}

func TestRedactBody_NoFalsePositives(t *testing.T) {
	safe := `{"name": "John", "email": "john@example.com", "role": "admin"}`
	result := redactBody(safe)
	if result != safe {
		t.Errorf("non-sensitive body was modified: %s", result)
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{
			"https://user:pass@example.com/path",
			"https://[REDACTED]@example.com/path",
		},
		{
			"https://example.com/path",
			"https://example.com/path",
		},
	}

	for _, tt := range tests {
		result := RedactURL(tt.input)
		if result != tt.expect {
			t.Errorf("RedactURL(%q) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}

func TestComputeEvidenceHash_Deterministic(t *testing.T) {
	ev := &Evidence{
		Request:  HTTPRequest{Method: "GET", URL: "https://example.com/test"},
		Response: HTTPResponse{StatusCode: 200, Body: "ok"},
		TimingMs: 50,
	}

	hash1 := computeEvidenceHash(ev)
	hash2 := computeEvidenceHash(ev)

	if hash1 != hash2 {
		t.Fatal("evidence hash is not deterministic")
	}
	if len(hash1) != 64 { // SHA-256 hex
		t.Fatalf("unexpected hash length: %d", len(hash1))
	}
}

func TestCaptureEvidence_HeaderRedaction(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("X-API-Key", "my-api-key")
	req.Header.Set("Content-Type", "application/json")

	ev := &Evidence{}
	captured := captureRequest(req)
	ev.Request = captured

	if captured.Headers["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization header not redacted: %s", captured.Headers["Authorization"])
	}
	if captured.Headers["X-Api-Key"] != "[REDACTED]" {
		t.Errorf("X-API-Key header not redacted: %s", captured.Headers["X-Api-Key"])
	}
	if captured.Headers["Content-Type"] != "application/json" {
		t.Error("Content-Type should not be redacted")
	}
}
