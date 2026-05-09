package dast

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/replay"
	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

// sec-03: a tampered action list with a navigate URL pointing outside the
// bundle's TargetHost must be rejected by the replay engine's pre-flight
// host-match check, before any browser is launched.
func TestSec03_ForgedActionListRejected(t *testing.T) {
	e := replay.NewEngine()
	b := &bundles.Bundle{
		ID:         "sec03-forged",
		Type:       "recorded_login",
		TargetHost: "app.bank.tld",
		ExpiresAt:  time.Now().Add(time.Hour),
		Actions: []bundles.Action{
			{Kind: bundles.ActionNavigate, URL: "https://app.bank.tld/login"},
			{Kind: bundles.ActionNavigate, URL: "https://evil.example.com/exfil"},
		},
	}

	_, err := e.Replay(context.Background(), b)
	if err == nil {
		t.Fatal("expected pre-flight rejection for navigate outside target host")
	}
	if !strings.Contains(err.Error(), "scope violation") {
		t.Fatalf("expected scope violation error, got: %v", err)
	}
}

// sec-04: per-bundle rate limit must reject a second replay within the
// configured interval.
func TestSec04_ReplayRateLimit(t *testing.T) {
	rl := replay.NewRateLimit()
	if err := rl.Allow("b1", "app.bank.tld"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := rl.Allow("b1", "app.bank.tld"); err == nil {
		t.Fatal("expected rate-limit rejection on immediate repeat")
	}
}
