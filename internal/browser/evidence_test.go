package browser

import (
	"strings"
	"testing"
)

func TestRedactCDPHeaders(t *testing.T) {
	headers := map[string]interface{}{
		"Authorization": "Bearer secret-token-123",
		"Content-Type":  "application/json",
		"Cookie":        "session=abc123",
		"X-Api-Key":     "key-456",
		"Accept":        "text/html",
	}

	result := RedactCDPHeaders(headers)

	if result["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization should be redacted, got %q", result["Authorization"])
	}
	if result["Cookie"] != "[REDACTED]" {
		t.Errorf("Cookie should be redacted, got %q", result["Cookie"])
	}
	if result["X-Api-Key"] != "[REDACTED]" {
		t.Errorf("X-Api-Key should be redacted, got %q", result["X-Api-Key"])
	}
	if result["Content-Type"] != "application/json" {
		t.Errorf("Content-Type should not be redacted, got %q", result["Content-Type"])
	}
	if result["Accept"] != "text/html" {
		t.Errorf("Accept should not be redacted, got %q", result["Accept"])
	}
}

func TestRedactBody(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		check func(string) bool
	}{
		{
			name: "password field",
			body: `{"password": "mysecretpass123"}`,
			check: func(s string) bool {
				return !strings.Contains(s, "mysecretpass123")
			},
		},
		{
			name: "bearer token",
			body: `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123`,
			check: func(s string) bool {
				return !strings.Contains(s, "eyJhbGciOiJIUzI1NiJ9")
			},
		},
		{
			name: "AWS key",
			body: `aws_key=AKIAIOSFODNN7EXAMPLE`,
			check: func(s string) bool {
				return !strings.Contains(s, "AKIAIOSFODNN7EXAMPLE")
			},
		},
		{
			name: "no sensitive data",
			body: `{"name": "John", "status": "ok"}`,
			check: func(s string) bool {
				return s == `{"name": "John", "status": "ok"}`
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactBody(tt.body)
			if !tt.check(result) {
				t.Errorf("RedactBody failed for %q: got %q", tt.name, result)
			}
		})
	}
}

func TestCaptureScreenshot_NilContext(t *testing.T) {
	ev, bytes, err := CaptureScreenshot(nil, "job-1", "rule-1")
	if err == nil {
		t.Error("expected error for nil context")
	}
	if ev != nil {
		t.Error("expected nil evidence for nil context")
	}
	if bytes != nil {
		t.Error("expected nil bytes for nil context")
	}
}
