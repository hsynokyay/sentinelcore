package browser

import (
	"context"
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// testEnforcer creates a scope enforcer that allows example.com with a mock resolver.
func testEnforcer(hosts ...string) *scope.Enforcer {
	resolverIPs := make(map[string][]net.IPAddr)
	pinnedIPs := make(map[string][]net.IP)
	ip := net.ParseIP("93.184.216.34")
	for _, h := range hosts {
		resolverIPs[h] = []net.IPAddr{{IP: ip}}
		pinnedIPs[h] = []net.IP{ip}
	}
	return scope.NewEnforcer(scope.Config{
		AllowedHosts: hosts,
		PinnedIPs:    pinnedIPs,
		Resolver:     &mockResolver{ips: resolverIPs},
	}, zerolog.Nop())
}

func TestCrawler_NewCrawler(t *testing.T) {
	enforcer := testEnforcer("example.com")
	c := NewCrawler(enforcer, zerolog.Nop())
	if c == nil {
		t.Fatal("NewCrawler returned nil")
	}
	if c.enforcer != enforcer {
		t.Error("enforcer not set correctly")
	}
}

func TestCrawler_ScopeFilteringLinks(t *testing.T) {
	// Simulate what the crawler does: scope-check before enqueue.
	enforcer := testEnforcer("example.com")

	job := BrowserScanJob{MaxURLs: 100, MaxDepth: 5}
	state := NewCrawlState(job)

	// These URLs simulate discovered links that must be scope-checked.
	discoveredLinks := []string{
		"https://example.com/page1",
		"https://evil.com/steal",
		"https://example.com/page2",
		"https://attacker.net/phish",
	}

	ctx := context.Background()
	depth := 1
	for _, link := range discoveredLinks {
		if enforcer.CheckRequest(ctx, link) == nil {
			state.Enqueue(link, depth)
		}
	}

	// Only in-scope URLs should be enqueued.
	if len(state.Queue) != 2 {
		t.Errorf("expected 2 in-scope URLs enqueued, got %d", len(state.Queue))
	}
	for _, entry := range state.Queue {
		if entry.URL != "https://example.com/page1" && entry.URL != "https://example.com/page2" {
			t.Errorf("unexpected URL in queue: %s", entry.URL)
		}
	}
}

func TestCrawler_FormDiscovery_MarksSafeAndUnsafe(t *testing.T) {
	tests := []struct {
		name       string
		action     string
		buttonText string
		wantSafe   bool
	}{
		{
			name:     "search form is safe",
			action:   "/search",
			wantSafe: true,
		},
		{
			name:     "login form is safe",
			action:   "/login",
			wantSafe: true,
		},
		{
			name:     "delete action is unsafe",
			action:   "/api/delete-account",
			wantSafe: false,
		},
		{
			name:     "purchase action is unsafe",
			action:   "/checkout/purchase",
			wantSafe: false,
		},
		{
			name:       "safe action with destructive button text is unsafe",
			action:     "/api/action",
			buttonText: "Delete All",
			wantSafe:   false,
		},
		{
			name:     "transfer action is unsafe",
			action:   "/bank/transfer",
			wantSafe: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destructive := IsDestructiveAction(tt.action)
			if !destructive && tt.buttonText != "" {
				destructive = IsDestructiveAction(tt.buttonText)
			}
			isSafe := !destructive

			if isSafe != tt.wantSafe {
				t.Errorf("action=%q buttonText=%q: got IsSafe=%v, want %v",
					tt.action, tt.buttonText, isSafe, tt.wantSafe)
			}
		})
	}
}

func TestCrawler_FormCSRFDetection(t *testing.T) {
	tests := []struct {
		name     string
		fields   []FormField
		wantCSRF bool
	}{
		{
			name: "csrf_token field detected",
			fields: []FormField{
				{Name: "username", Type: "text"},
				{Name: "csrf_token", Type: "hidden", Value: "abc123"},
			},
			wantCSRF: true,
		},
		{
			name: "_token field detected",
			fields: []FormField{
				{Name: "email", Type: "email"},
				{Name: "_token", Type: "hidden", Value: "xyz"},
			},
			wantCSRF: true,
		},
		{
			name: "XCSRF-Token field detected (case insensitive)",
			fields: []FormField{
				{Name: "X-CSRF-Token", Type: "hidden", Value: "tok"},
			},
			wantCSRF: true,
		},
		{
			name: "no CSRF field",
			fields: []FormField{
				{Name: "username", Type: "text"},
				{Name: "password", Type: "password"},
			},
			wantCSRF: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasCSRF := false
			for _, f := range tt.fields {
				if IsCSRFField(f.Name) {
					hasCSRF = true
					break
				}
			}
			if hasCSRF != tt.wantCSRF {
				t.Errorf("got HasCSRF=%v, want %v", hasCSRF, tt.wantCSRF)
			}
		})
	}
}

func TestCrawler_DepthTracking(t *testing.T) {
	job := BrowserScanJob{MaxURLs: 100, MaxDepth: 3}
	state := NewCrawlState(job)

	// Simulate a chain: depth 0 -> 1 -> 2 -> 3 -> 4 (rejected)
	if !state.Enqueue("https://example.com/", 0) {
		t.Fatal("depth 0 should be accepted")
	}
	if !state.Enqueue("https://example.com/a", 1) {
		t.Fatal("depth 1 should be accepted")
	}
	if !state.Enqueue("https://example.com/b", 2) {
		t.Fatal("depth 2 should be accepted")
	}
	if !state.Enqueue("https://example.com/c", 3) {
		t.Fatal("depth 3 (== MaxDepth) should be accepted")
	}
	// Depth 4 exceeds MaxDepth=3, must be rejected.
	if state.Enqueue("https://example.com/d", 4) {
		t.Error("depth 4 (> MaxDepth 3) should be rejected")
	}

	// Verify queue has exactly 4 entries at depths 0-3.
	if len(state.Queue) != 4 {
		t.Errorf("expected 4 queued entries, got %d", len(state.Queue))
	}
}

func TestFormInfo_IsDestructive(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{"delete", true},
		{"DELETE", true},
		{"/api/remove-user", true},
		{"/cancel-subscription", true},
		{"/pay/invoice", true},
		{"/purchase/complete", true},
		{"/transfer/funds", true},
		{"/send-notification", true},
		{"/destroy-session", true},
		{"/drop-table", true},
		{"/terminate-instance", true},
		{"/revoke-access", true},
		{"/search", false},
		{"/login", false},
		{"/profile/update", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := IsDestructiveAction(tt.text)
			if got != tt.want {
				t.Errorf("IsDestructiveAction(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestFormInfo_CSRFDetection(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"csrf_token", true},
		{"_token", true},
		{"_csrf", true},
		{"X-CSRF-Token", true},
		{"xcsrf", true},
		{"authenticity_token", true}, // contains _token
		{"username", false},
		{"password", false},
		{"email", false},
		{"submit", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCSRFField(tt.name)
			if got != tt.want {
				t.Errorf("IsCSRFField(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
