package recording

import (
	"testing"
	"time"
)

func TestNew_DefaultsTimeout(t *testing.T) {
	r := New(Options{TargetURL: "https://app.bank.tld/login"})
	if r.opts.Timeout != 10*time.Minute {
		t.Errorf("expected 10min default, got %v", r.opts.Timeout)
	}
}

func TestNew_CustomTimeout(t *testing.T) {
	r := New(Options{TargetURL: "https://x.tld", Timeout: 5 * time.Minute})
	if r.opts.Timeout != 5*time.Minute {
		t.Errorf("expected 5min, got %v", r.opts.Timeout)
	}
}

func TestHostAllowed_Empty(t *testing.T) {
	if !hostAllowed("any.example.com", nil) {
		t.Error("expected nil allowed list to permit any host")
	}
}

func TestHostAllowed_ExactMatch(t *testing.T) {
	if !hostAllowed("app.bank.tld", []string{"app.bank.tld"}) {
		t.Error("expected exact match to pass")
	}
}

func TestHostAllowed_DotPrefixed(t *testing.T) {
	if !hostAllowed(".app.bank.tld", []string{"app.bank.tld"}) {
		t.Error("expected dot-prefixed cookie domain to match")
	}
}

func TestHostAllowed_NoMatch(t *testing.T) {
	if hostAllowed("evil.bank.tld", []string{"app.bank.tld"}) {
		t.Error("expected non-matching host to be rejected")
	}
}

func TestRecorder_LiveBrowserSkipped(t *testing.T) {
	t.Skip("requires Chrome binary; covered by integration tests when CHROME_BINARY set")
}
