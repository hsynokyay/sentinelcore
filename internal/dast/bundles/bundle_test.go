package bundles

import (
	"bytes"
	"testing"
	"time"
)

func sampleBundle() *Bundle {
	return &Bundle{
		ID:              "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		SchemaVersion:   1,
		CustomerID:      "cccccccc-cccc-cccc-cccc-cccccccccccc",
		ProjectID:       "pppppppp-pppp-pppp-pppp-pppppppppppp",
		TargetHost:      "app.example.tld",
		TargetPrincipal: "user@example.tld",
		Type:            "session_import",
		CapturedSession: SessionCapture{
			Cookies: []Cookie{
				{Name: "JSESSIONID", Value: "abc123", Domain: "app.example.tld", Path: "/"},
				{Name: "XSRF-TOKEN", Value: "tok", HttpOnly: true, Secure: true},
			},
			Headers: map[string]string{
				"Authorization": "Bearer xyz",
				"X-Custom":      "val",
			},
		},
		CreatedByUserID: "uuuuuuuu-uuuu-uuuu-uuuu-uuuuuuuuuuuu",
		CreatedAt:       time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC),
		TTLSeconds:      86400,
	}
}

func TestCanonicalJSON_Deterministic(t *testing.T) {
	b := sampleBundle()

	first, err := b.CanonicalJSON()
	if err != nil {
		t.Fatalf("first CanonicalJSON: %v", err)
	}
	second, err := b.CanonicalJSON()
	if err != nil {
		t.Fatalf("second CanonicalJSON: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("CanonicalJSON is not deterministic:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestIntegrityHMAC_VerifyRoundTrip(t *testing.T) {
	b := sampleBundle()
	key := []byte("test-hmac-key-32-bytes-of-entropy")

	mac, err := b.ComputeIntegrityHMAC(key)
	if err != nil {
		t.Fatalf("ComputeIntegrityHMAC: %v", err)
	}

	ok, err := b.VerifyIntegrityHMAC(key, mac)
	if err != nil {
		t.Fatalf("VerifyIntegrityHMAC: %v", err)
	}
	if !ok {
		t.Error("VerifyIntegrityHMAC returned false for valid MAC")
	}
}

func TestIntegrityHMAC_TamperedFails(t *testing.T) {
	b := sampleBundle()
	key := []byte("test-hmac-key-32-bytes-of-entropy")

	mac, err := b.ComputeIntegrityHMAC(key)
	if err != nil {
		t.Fatalf("ComputeIntegrityHMAC: %v", err)
	}

	// Tamper with the bundle.
	b.TargetHost = "evil.attacker.tld"

	ok, err := b.VerifyIntegrityHMAC(key, mac)
	if err != nil {
		t.Fatalf("VerifyIntegrityHMAC: %v", err)
	}
	if ok {
		t.Error("VerifyIntegrityHMAC returned true for tampered bundle — integrity check bypassed")
	}
}
