package replay

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

func TestPreflight_HostMatch_Pass(t *testing.T) {
	b := &bundles.Bundle{
		TargetHost: "app.bank.tld",
		Actions: []bundles.Action{
			{Kind: bundles.ActionNavigate, URL: "https://app.bank.tld/login"},
			{Kind: bundles.ActionNavigate, URL: "https://app.bank.tld/dashboard"},
		},
	}
	if err := preflightHostMatch(b, "app.bank.tld"); err != nil {
		t.Fatalf("expected pass: %v", err)
	}
}

func TestPreflight_HostMatch_ScopeViolation(t *testing.T) {
	b := &bundles.Bundle{
		TargetHost: "app.bank.tld",
		Actions: []bundles.Action{
			{Kind: bundles.ActionNavigate, URL: "https://app.bank.tld/login"},
			{Kind: bundles.ActionNavigate, URL: "https://evil.com/exfil"},
		},
	}
	err := preflightHostMatch(b, "app.bank.tld")
	if err == nil {
		t.Fatal("expected scope violation error")
	}
}

func TestPreflight_NoTargetHost(t *testing.T) {
	b := &bundles.Bundle{Actions: []bundles.Action{{Kind: bundles.ActionNavigate, URL: "https://x"}}}
	if err := preflightHostMatch(b, ""); err == nil {
		t.Fatal("expected error on empty target host")
	}
}

func TestRateLimit_BlocksRepeatWithinInterval(t *testing.T) {
	rl := NewRateLimit()
	if err := rl.Allow("b1", "app.bank.tld"); err != nil {
		t.Fatalf("first call should pass: %v", err)
	}
	if err := rl.Allow("b1", "app.bank.tld"); err == nil {
		t.Fatal("expected rate-limit on immediate repeat")
	}
}

func TestRateLimit_AllowsAfterInterval(t *testing.T) {
	rl := NewRateLimit()
	rl.SetInterval(10 * time.Millisecond)
	_ = rl.Allow("b1", "app.bank.tld")
	time.Sleep(15 * time.Millisecond)
	if err := rl.Allow("b1", "app.bank.tld"); err != nil {
		t.Fatalf("expected allow after interval: %v", err)
	}
}

func TestRateLimit_SeparateBundles(t *testing.T) {
	rl := NewRateLimit()
	if err := rl.Allow("b1", "host"); err != nil { t.Fatal(err) }
	if err := rl.Allow("b2", "host"); err != nil {
		t.Fatal("different bundle should not be rate-limited")
	}
}

func TestEngine_NilBundle(t *testing.T) {
	e := NewEngine()
	_, err := e.Replay(context.Background(), nil)
	if err == nil {
		t.Fatal("expected nil-bundle error")
	}
}

func TestEngine_WrongType(t *testing.T) {
	e := NewEngine()
	b := &bundles.Bundle{
		Type: "session_import",
		ExpiresAt: time.Now().Add(time.Hour),
		Actions: []bundles.Action{{Kind: bundles.ActionNavigate, URL: "https://x/"}},
	}
	_, err := e.Replay(context.Background(), b)
	if err == nil {
		t.Fatal("expected wrong-type error")
	}
}

func TestEngine_NoActions(t *testing.T) {
	e := NewEngine()
	b := &bundles.Bundle{Type: "recorded_login", ExpiresAt: time.Now().Add(time.Hour)}
	_, err := e.Replay(context.Background(), b)
	if err == nil {
		t.Fatal("expected no-actions error")
	}
}

func TestEngine_LiveBrowserSkipped(t *testing.T) {
	t.Skip("live chromedp run requires Chrome binary")
}

func TestEngine_Replay_PrincipalMismatch(t *testing.T) {
	e := NewEngine()
	b := &bundles.Bundle{
		ID:              "11111111-1111-1111-1111-111111111111",
		Type:            "recorded_login",
		TargetHost:      "app.bank.tld",
		TargetPrincipal: "alice",
		ExpiresAt:       time.Now().Add(time.Hour),
		Actions: []bundles.Action{
			{Kind: bundles.ActionNavigate, URL: "https://app.bank.tld/x"},
		},
	}
	ctx := ContextWithExpectedPrincipal(context.Background(), "bob")
	_, err := e.Replay(ctx, b)
	if err == nil || !strings.Contains(err.Error(), "principal") {
		t.Fatalf("expected principal mismatch, got %v", err)
	}
}

func TestEngine_Replay_PrincipalNoBindingPasses(t *testing.T) {
	// When the scan didn't supply an expected principal, replay must not
	// fail on principal grounds (it'll fail later trying to launch chromedp,
	// which is fine — we only assert the *order*: principal check is a no-op).
	e := NewEngine()
	b := &bundles.Bundle{
		ID:              "11111111-1111-1111-1111-111111111111",
		Type:            "recorded_login",
		TargetHost:      "app.bank.tld",
		TargetPrincipal: "alice",
		ExpiresAt:       time.Now().Add(time.Hour),
		Actions: []bundles.Action{
			{Kind: bundles.ActionNavigate, URL: "https://app.bank.tld/x"},
		},
	}
	// No ContextWithExpectedPrincipal call — scan didn't supply one.
	_, err := e.Replay(context.Background(), b)
	if err != nil && strings.Contains(err.Error(), "principal") {
		t.Fatalf("principal must not error when scan-expected is empty, got %v", err)
	}
}

func TestContextWithExpectedPrincipal_RoundTrip(t *testing.T) {
	ctx := ContextWithExpectedPrincipal(context.Background(), "carol")
	got, _ := ctx.Value(scanPrincipalKey{}).(string)
	if got != "carol" {
		t.Fatalf("got=%q want=carol", got)
	}
}
