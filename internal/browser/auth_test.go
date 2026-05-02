package browser

import (
	"net"
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

func TestShouldInjectAuth(t *testing.T) {
	enforcer := newTestEnforcer([]string{"example.com"})

	if !ShouldInjectAuth("https://example.com/api", enforcer) {
		t.Error("expected true for in-scope URL")
	}
	if ShouldInjectAuth("https://evil.com/steal", enforcer) {
		t.Error("expected false for out-of-scope URL")
	}
}

func TestInjectCookies_RejectsThirdParty(t *testing.T) {
	// isDomainAllowed is the key function — test it directly.
	allowed := []string{"example.com"}

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{".example.com", true},
		{"sub.example.com", true},
		{"evil.com", false},
		{"notexample.com", false},
		{"com", false},
	}

	for _, tt := range tests {
		got := isDomainAllowed(tt.domain, allowed)
		if got != tt.want {
			t.Errorf("isDomainAllowed(%q, %v) = %v, want %v", tt.domain, allowed, got, tt.want)
		}
	}
}

func TestInjectCookies_NilSession(t *testing.T) {
	err := InjectCookies(nil, nil, []string{"example.com"})
	if err == nil {
		t.Error("expected error for nil session")
	}
}

func TestShouldInjectAuth_PrivateIP(t *testing.T) {
	// Host that resolves to a private IP should fail scope check.
	enforcer := scope.NewEnforcer(scope.Config{
		AllowedHosts: []string{"internal.local"},
		PinnedIPs: map[string][]net.IP{
			"internal.local": {net.ParseIP("10.0.0.5")},
		},
		Resolver: &mockResolver{ips: map[string][]net.IPAddr{
			"internal.local": {{IP: net.ParseIP("10.0.0.5")}},
		}},
	}, zerolog.Nop())

	if ShouldInjectAuth("https://internal.local/api", enforcer) {
		t.Error("should not inject auth for private IP target")
	}
}

func TestInjectCookies_SkipsThirdPartyCookies(t *testing.T) {
	session := &authbroker.Session{
		Cookies: []*http.Cookie{
			{Name: "ok", Value: "v1", Domain: "example.com"},
			{Name: "bad", Value: "v2", Domain: "evil.com"},
		},
	}

	// We cannot actually call InjectCookies without a real Chrome context,
	// so we test the filtering logic directly.
	allowed := []string{"example.com"}
	for _, c := range session.Cookies {
		domain := c.Domain
		if c.Domain == "evil.com" && isDomainAllowed(domain, allowed) {
			t.Error("evil.com cookie should be rejected")
		}
		if c.Domain == "example.com" && !isDomainAllowed(domain, allowed) {
			t.Error("example.com cookie should be allowed")
		}
	}
}
