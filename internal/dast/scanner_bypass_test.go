package dast

import (
	"context"
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// newTestBypassKMS returns a LocalProvider with a fixed 32-byte master key.
// The plan's test string "test-master-key-32-bytes-of-entropy!" is 36 bytes
// which would panic; we use a deterministic 32-byte key instead.
func newTestBypassKMS() kms.Provider {
	master := make([]byte, 32)
	copy(master, []byte("test-master-key-32-bytes--------"))
	return kms.NewLocalProvider(master)
}

func TestBypassToken_RoundTrip(t *testing.T) {
	k := newTestBypassKMS()
	issuer := NewBypassTokenIssuer(k, "bypass-key", time.Now)
	ctx := context.Background()
	tok, err := issuer.Issue(ctx, "scan-job-1", "app.bank.tld")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v, err := issuer.Verify(ctx, tok, "app.bank.tld")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.ScanJobID != "scan-job-1" {
		t.Errorf("ScanJobID: got %q", v.ScanJobID)
	}
}

func TestBypassToken_WrongHost(t *testing.T) {
	k := newTestBypassKMS()
	issuer := NewBypassTokenIssuer(k, "bypass-key", time.Now)
	ctx := context.Background()
	tok, _ := issuer.Issue(ctx, "scan-job-1", "app.bank.tld")
	if _, err := issuer.Verify(ctx, tok, "evil.bank.tld"); err == nil {
		t.Fatal("expected verification to fail for wrong host")
	}
}

func TestBypassToken_Expired(t *testing.T) {
	k := newTestBypassKMS()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	issuer := NewBypassTokenIssuer(k, "bypass-key", clock)
	ctx := context.Background()
	tok, _ := issuer.Issue(ctx, "scan-job-1", "app.bank.tld")
	now = now.Add(6 * time.Minute)
	if _, err := issuer.Verify(ctx, tok, "app.bank.tld"); err == nil {
		t.Fatal("expected window expiry rejection")
	}
}

func TestBypassToken_NonceReuse(t *testing.T) {
	k := newTestBypassKMS()
	issuer := NewBypassTokenIssuer(k, "bypass-key", time.Now)
	ctx := context.Background()
	tok, _ := issuer.Issue(ctx, "scan-job-1", "app.bank.tld")
	if _, err := issuer.Verify(ctx, tok, "app.bank.tld"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := issuer.Verify(ctx, tok, "app.bank.tld"); err == nil {
		t.Fatal("expected replay to be rejected")
	}
}
