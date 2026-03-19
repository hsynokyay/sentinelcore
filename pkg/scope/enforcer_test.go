package scope

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// mockResolver returns preconfigured DNS results for testing.
type mockResolver struct {
	results map[string][]net.IPAddr
	err     error
}

func (m *mockResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if m.err != nil {
		return nil, m.err
	}
	addrs, ok := m.results[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return addrs, nil
}

func newTestEnforcer(hosts []string, pinnedIPs map[string][]net.IP, resolver Resolver) *Enforcer {
	cfg := Config{
		AllowedHosts:  hosts,
		PinnedIPs:     pinnedIPs,
		MaxViolations: 5,
		Resolver:      resolver,
	}
	return NewEnforcer(cfg, zerolog.Nop())
}

func TestCheckRequest_AllowedHost(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("93.184.216.34")}},
		},
	}
	pinned := map[string][]net.IP{
		"example.com": {net.ParseIP("93.184.216.34")},
	}
	e := newTestEnforcer([]string{"example.com"}, pinned, resolver)

	err := e.CheckRequest(context.Background(), "https://example.com/api/v1/test")
	if err != nil {
		t.Fatalf("expected request to be allowed, got: %v", err)
	}
}

func TestCheckRequest_DisallowedHost(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"evil.com": {{IP: net.ParseIP("1.2.3.4")}},
		},
	}
	e := newTestEnforcer([]string{"example.com"}, nil, resolver)

	err := e.CheckRequest(context.Background(), "https://evil.com/steal-data")
	if err == nil {
		t.Fatal("expected request to be blocked")
	}
}

func TestCheckRequest_BlockedIP(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com": {{IP: net.ParseIP("169.254.169.254")}},
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("169.254.169.254")},
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)

	err := e.CheckRequest(context.Background(), "https://target.com/metadata")
	if err == nil {
		t.Fatal("expected cloud metadata IP to be blocked")
	}
}

func TestCheckRequest_DNSRebinding(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com": {{IP: net.ParseIP("1.1.1.1")}}, // resolves to different IP
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("93.184.216.34")}, // pinned to original
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)

	err := e.CheckRequest(context.Background(), "https://target.com/api")
	if err == nil {
		t.Fatal("expected DNS rebinding to be detected")
	}
}

func TestCheckRequest_InvalidScheme(t *testing.T) {
	resolver := &mockResolver{results: map[string][]net.IPAddr{}}
	e := newTestEnforcer([]string{"example.com"}, nil, resolver)

	err := e.CheckRequest(context.Background(), "ftp://example.com/file")
	if err == nil {
		t.Fatal("expected FTP scheme to be blocked")
	}
}

func TestCheckRedirect_MaxRedirects(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("93.184.216.34")}},
		},
	}
	pinned := map[string][]net.IP{
		"example.com": {net.ParseIP("93.184.216.34")},
	}
	cfg := Config{
		AllowedHosts:  []string{"example.com"},
		PinnedIPs:     pinned,
		MaxRedirects:  3,
		Resolver:      resolver,
	}
	e := NewEnforcer(cfg, zerolog.Nop())

	err := e.CheckRedirect(context.Background(), "https://example.com/redirect", 3)
	if err == nil {
		t.Fatal("expected max redirects to be enforced")
	}
}

func TestCheckRequest_AutoAbort(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{},
	}
	e := newTestEnforcer([]string{"example.com"}, nil, resolver)

	// Generate violations by requesting disallowed hosts
	for i := 0; i < 5; i++ {
		_ = e.CheckRequest(context.Background(), fmt.Sprintf("https://evil%d.com/path", i))
	}

	if !e.IsAborted() {
		t.Fatal("expected enforcer to trigger abort after max violations")
	}

	// Subsequent requests should fail with abort message
	err := e.CheckRequest(context.Background(), "https://example.com/api")
	if err == nil {
		t.Fatal("expected aborted enforcer to reject all requests")
	}
}

func TestPinHosts_BlockedIP(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"internal.target": {{IP: net.ParseIP("10.0.0.1")}},
		},
	}
	cfg := Config{
		AllowedHosts: []string{"internal.target"},
		Resolver:     resolver,
	}
	e := NewEnforcer(cfg, zerolog.Nop())

	err := e.PinHosts(context.Background())
	if err == nil {
		t.Fatal("expected PinHosts to reject internal IP")
	}
}

func TestPinHosts_AllowPrivateIPs(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"internal.target": {{IP: net.ParseIP("10.0.0.1")}},
		},
	}
	cfg := Config{
		AllowedHosts:    []string{"internal.target"},
		AllowPrivateIPs: true,
		Resolver:        resolver,
	}
	e := NewEnforcer(cfg, zerolog.Nop())

	err := e.PinHosts(context.Background())
	if err != nil {
		t.Fatalf("expected PinHosts to allow private IPs with flag: %v", err)
	}
}

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"100.64.0.1", true},     // carrier-grade NAT
		{"240.0.0.1", true},      // reserved
		{"93.184.216.34", false},  // public IP
		{"8.8.8.8", false},       // Google DNS
		{"1.1.1.1", false},       // Cloudflare
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if IsBlockedIP(ip) != tt.blocked {
				t.Errorf("IsBlockedIP(%s) = %v, want %v", tt.ip, !tt.blocked, tt.blocked)
			}
		})
	}
}

func TestViolationCount(t *testing.T) {
	resolver := &mockResolver{results: map[string][]net.IPAddr{}}
	e := newTestEnforcer([]string{"example.com"}, nil, resolver)

	_ = e.CheckRequest(context.Background(), "https://evil.com/a")
	_ = e.CheckRequest(context.Background(), "https://evil2.com/b")

	if e.ViolationCount() != 2 {
		t.Fatalf("expected 2 violations, got %d", e.ViolationCount())
	}

	violations := e.Violations()
	if len(violations) != 2 {
		t.Fatalf("expected 2 violation records, got %d", len(violations))
	}
}

func TestNewScopedClient(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("93.184.216.34")}},
		},
	}
	pinned := map[string][]net.IP{
		"example.com": {net.ParseIP("93.184.216.34")},
	}
	e := newTestEnforcer([]string{"example.com"}, pinned, resolver)

	client := NewScopedClient(e, 5*time.Second)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != 5*time.Second {
		t.Fatalf("expected 5s timeout, got %v", client.Timeout)
	}
}

func TestCheckRequest_PrivateIPRanges(t *testing.T) {
	// SSRF attack: target resolves to various internal ranges
	privateIPs := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"127.0.0.1",
		"169.254.169.254",
		"0.0.0.1",
	}

	for _, ip := range privateIPs {
		t.Run(ip, func(t *testing.T) {
			resolver := &mockResolver{
				results: map[string][]net.IPAddr{
					"target.com": {{IP: net.ParseIP(ip)}},
				},
			}
			pinned := map[string][]net.IP{
				"target.com": {net.ParseIP(ip)},
			}
			e := newTestEnforcer([]string{"target.com"}, pinned, resolver)

			err := e.CheckRequest(context.Background(), "https://target.com/api")
			if err == nil {
				t.Fatalf("expected private IP %s to be blocked", ip)
			}
		})
	}
}

// --- Adversarial scope enforcement tests ---

func TestAdversarial_CloudMetadataSSRF(t *testing.T) {
	// AWS/GCP/Azure metadata endpoints via DNS rebinding
	metadataIPs := []string{
		"169.254.169.254", // AWS/Azure metadata
		"169.254.0.1",     // Link-local
	}
	for _, ip := range metadataIPs {
		t.Run(ip, func(t *testing.T) {
			resolver := &mockResolver{
				results: map[string][]net.IPAddr{
					"target.com": {{IP: net.ParseIP(ip)}},
				},
			}
			pinned := map[string][]net.IP{
				"target.com": {net.ParseIP(ip)},
			}
			e := newTestEnforcer([]string{"target.com"}, pinned, resolver)
			err := e.CheckRequest(context.Background(), "https://target.com/latest/meta-data/")
			if err == nil {
				t.Fatalf("cloud metadata IP %s should be blocked", ip)
			}
		})
	}
}

func TestAdversarial_IPv6LoopbackSSRF(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com": {{IP: net.ParseIP("::1")}},
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("::1")},
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)
	err := e.CheckRequest(context.Background(), "https://target.com/secret")
	if err == nil {
		t.Fatal("IPv6 loopback should be blocked")
	}
}

func TestAdversarial_IPv6UniqueLocalSSRF(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com": {{IP: net.ParseIP("fd00::1")}},
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("fd00::1")},
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)
	err := e.CheckRequest(context.Background(), "https://target.com/internal")
	if err == nil {
		t.Fatal("IPv6 unique local address should be blocked")
	}
}

func TestAdversarial_DNSRebindingMidScan(t *testing.T) {
	callCount := 0
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			// First call returns public IP, subsequent return private
			"target.com": {{IP: net.ParseIP("93.184.216.34")}},
		},
	}
	_ = callCount

	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("93.184.216.34")},
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)

	// First request succeeds
	err := e.CheckRequest(context.Background(), "https://target.com/api")
	if err != nil {
		t.Fatalf("first request should succeed: %v", err)
	}

	// Simulate DNS rebinding: change resolver to return different IP
	resolver.results["target.com"] = []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}

	// Second request should fail (new IP not in pinned set + private)
	err = e.CheckRequest(context.Background(), "https://target.com/api")
	if err == nil {
		t.Fatal("expected DNS rebinding to be detected")
	}
}

func TestAdversarial_RedirectToInternalHost(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com":   {{IP: net.ParseIP("93.184.216.34")}},
			"internal.corp": {{IP: net.ParseIP("10.0.0.50")}},
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("93.184.216.34")},
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)

	// Redirect to internal host should be blocked (not in allowed hosts)
	err := e.CheckRedirect(context.Background(), "https://internal.corp/admin", 1)
	if err == nil {
		t.Fatal("redirect to internal host should be blocked")
	}
}

func TestAdversarial_RedirectChainExhaustion(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com": {{IP: net.ParseIP("93.184.216.34")}},
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("93.184.216.34")},
	}
	cfg := Config{
		AllowedHosts: []string{"target.com"},
		PinnedIPs:    pinned,
		MaxRedirects: 5,
		Resolver:     resolver,
	}
	e := NewEnforcer(cfg, zerolog.Nop())

	// Redirects within limit should work
	for i := 0; i < 5; i++ {
		err := e.CheckRedirect(context.Background(), "https://target.com/page", i)
		if err != nil {
			t.Fatalf("redirect %d should be allowed: %v", i, err)
		}
	}

	// Redirect at limit should fail
	err := e.CheckRedirect(context.Background(), "https://target.com/page", 5)
	if err == nil {
		t.Fatal("redirect chain at max should be blocked")
	}
}

func TestAdversarial_SchemeDowngrade(t *testing.T) {
	resolver := &mockResolver{results: map[string][]net.IPAddr{}}
	e := newTestEnforcer([]string{"target.com"}, nil, resolver)

	schemes := []string{"file:///etc/passwd", "gopher://target.com/", "dict://target.com/", "ldap://target.com/"}
	for _, u := range schemes {
		t.Run(u, func(t *testing.T) {
			err := e.CheckRequest(context.Background(), u)
			if err == nil {
				t.Fatalf("scheme %s should be blocked", u)
			}
		})
	}
}

func TestAdversarial_CarrierGradeNAT(t *testing.T) {
	// 100.64.0.0/10 (CGNAT) should be blocked
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com": {{IP: net.ParseIP("100.64.0.1")}},
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("100.64.0.1")},
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)
	err := e.CheckRequest(context.Background(), "https://target.com/api")
	if err == nil {
		t.Fatal("CGNAT address should be blocked")
	}
}

func TestAdversarial_ReservedRange240(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com": {{IP: net.ParseIP("240.0.0.1")}},
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("240.0.0.1")},
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)
	err := e.CheckRequest(context.Background(), "https://target.com/api")
	if err == nil {
		t.Fatal("reserved 240.0.0.0/4 should be blocked")
	}
}

func TestAdversarial_DocumentationRange(t *testing.T) {
	// 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
	docIPs := []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}
	for _, ip := range docIPs {
		t.Run(ip, func(t *testing.T) {
			resolver := &mockResolver{
				results: map[string][]net.IPAddr{
					"target.com": {{IP: net.ParseIP(ip)}},
				},
			}
			pinned := map[string][]net.IP{
				"target.com": {net.ParseIP(ip)},
			}
			e := newTestEnforcer([]string{"target.com"}, pinned, resolver)
			err := e.CheckRequest(context.Background(), "https://target.com/api")
			if err == nil {
				t.Fatalf("documentation IP %s should be blocked", ip)
			}
		})
	}
}

func TestAdversarial_MultipleIPsPartialRebind(t *testing.T) {
	// Target has 2 IPs, one rebinds to internal
	resolver := &mockResolver{
		results: map[string][]net.IPAddr{
			"target.com": {
				{IP: net.ParseIP("93.184.216.34")},
				{IP: net.ParseIP("10.0.0.1")}, // rebind to internal
			},
		},
	}
	pinned := map[string][]net.IP{
		"target.com": {net.ParseIP("93.184.216.34"), net.ParseIP("93.184.216.35")},
	}
	e := newTestEnforcer([]string{"target.com"}, pinned, resolver)
	err := e.CheckRequest(context.Background(), "https://target.com/api")
	if err == nil {
		t.Fatal("partial rebind to internal IP should be blocked")
	}
}

func TestAdversarial_EmptyHostname(t *testing.T) {
	resolver := &mockResolver{results: map[string][]net.IPAddr{}}
	e := newTestEnforcer([]string{"target.com"}, nil, resolver)
	err := e.CheckRequest(context.Background(), "https:///path")
	if err == nil {
		t.Fatal("empty hostname should be blocked")
	}
}

func TestAdversarial_ConcurrentViolationCounting(t *testing.T) {
	resolver := &mockResolver{results: map[string][]net.IPAddr{}}
	cfg := Config{
		AllowedHosts:  []string{"target.com"},
		MaxViolations: 100,
		Resolver:      resolver,
	}
	e := NewEnforcer(cfg, zerolog.Nop())

	// Fire 50 concurrent violations
	done := make(chan struct{}, 50)
	for i := 0; i < 50; i++ {
		go func(i int) {
			e.CheckRequest(context.Background(), fmt.Sprintf("https://evil%d.com/path", i))
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}

	if e.ViolationCount() != 50 {
		t.Fatalf("expected 50 violations, got %d", e.ViolationCount())
	}
}
