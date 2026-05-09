package dast

import (
	"context"
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// sec-01: Tampered ciphertext fails decryption.
func TestSec01_TamperedCiphertext(t *testing.T) {
	p := kms.NewLocalProvider([]byte("test-master-key-32-bytes--------"))
	ctx := context.Background()
	env, err := kms.EncryptEnvelope(ctx, p, "test", []byte("data"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	env.Ciphertext[0] ^= 0xFF
	if _, err := kms.DecryptEnvelope(ctx, p, env, []byte("aad")); err == nil {
		t.Fatal("expected tamper to be detected")
	}
}

// sec-02: Tampered wrapped DEK fails decryption.
func TestSec02_TamperedWrappedDEK(t *testing.T) {
	p := kms.NewLocalProvider([]byte("test-master-key-32-bytes--------"))
	ctx := context.Background()
	env, _ := kms.EncryptEnvelope(ctx, p, "test", []byte("data"), []byte("aad"))
	env.WrappedDEK[0] ^= 0xFF
	if _, err := kms.DecryptEnvelope(ctx, p, env, []byte("aad")); err == nil {
		t.Fatal("expected tamper to be detected")
	}
}

// sec-05: Forged token: HMAC over different target_host fails.
func TestSec05_ForgedTokenWrongHost(t *testing.T) {
	p := kms.NewLocalProvider([]byte("test-master-key-32-bytes--------"))
	issuer := NewBypassTokenIssuer(p, "bypass-key", time.Now)
	ctx := context.Background()
	tok, _ := issuer.Issue(ctx, "scan-1", "app.bank.tld")
	if _, err := issuer.Verify(ctx, tok, "evil.bank.tld"); err == nil {
		t.Fatal("expected forged-host verification to fail")
	}
}

// sec-06: Replay attack: same token used twice → second rejected.
func TestSec06_TokenReplay(t *testing.T) {
	p := kms.NewLocalProvider([]byte("test-master-key-32-bytes--------"))
	issuer := NewBypassTokenIssuer(p, "bypass-key", time.Now)
	ctx := context.Background()
	tok, _ := issuer.Issue(ctx, "scan-1", "app.bank.tld")
	if _, err := issuer.Verify(ctx, tok, "app.bank.tld"); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if _, err := issuer.Verify(ctx, tok, "app.bank.tld"); err == nil {
		t.Fatal("expected replay to be rejected")
	}
}

// sec-07: Token outside time window rejected.
func TestSec07_TokenOutsideWindow(t *testing.T) {
	p := kms.NewLocalProvider([]byte("test-master-key-32-bytes--------"))
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	issuer := NewBypassTokenIssuer(p, "bypass-key", clock)
	ctx := context.Background()
	tok, _ := issuer.Issue(ctx, "scan-1", "app.bank.tld")
	now = now.Add(10 * time.Minute)
	if _, err := issuer.Verify(ctx, tok, "app.bank.tld"); err == nil {
		t.Fatal("expected window expiry rejection")
	}
}
