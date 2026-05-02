package browser

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// mockResolver returns fixed IPs for testing, avoiding real DNS lookups.
type mockResolver struct {
	ips map[string][]net.IPAddr
}

func (m *mockResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if addrs, ok := m.ips[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func newTestEnforcer(hosts []string) *scope.Enforcer {
	publicIP := net.ParseIP("93.184.216.34")
	pinnedIPs := make(map[string][]net.IP)
	resolverIPs := make(map[string][]net.IPAddr)
	for _, h := range hosts {
		pinnedIPs[h] = []net.IP{publicIP}
		resolverIPs[h] = []net.IPAddr{{IP: publicIP}}
	}
	return scope.NewEnforcer(scope.Config{
		AllowedHosts: hosts,
		PinnedIPs:    pinnedIPs,
		Resolver:     &mockResolver{ips: resolverIPs},
	}, zerolog.Nop())
}

func TestDecide_Allow(t *testing.T) {
	enforcer := newTestEnforcer([]string{"example.com"})
	interceptor := NewInterceptor(enforcer, nil, zerolog.Nop())

	if d := interceptor.Decide("https://example.com/page"); d != Allow {
		t.Errorf("expected Allow for in-scope URL, got %d", d)
	}
	if interceptor.Violations() != 0 {
		t.Errorf("expected 0 violations, got %d", interceptor.Violations())
	}
}

func TestDecide_Block(t *testing.T) {
	enforcer := newTestEnforcer([]string{"example.com"})
	interceptor := NewInterceptor(enforcer, nil, zerolog.Nop())

	if d := interceptor.Decide("https://evil.com/steal"); d != Block {
		t.Errorf("expected Block for out-of-scope URL, got %d", d)
	}
	if interceptor.Violations() != 1 {
		t.Errorf("expected 1 violation, got %d", interceptor.Violations())
	}
}

func TestDecide_PrivateIP(t *testing.T) {
	enforcer := scope.NewEnforcer(scope.Config{
		AllowedHosts: []string{"internal.local"},
		PinnedIPs: map[string][]net.IP{
			"internal.local": {net.ParseIP("192.168.1.1")},
		},
		Resolver: &mockResolver{ips: map[string][]net.IPAddr{
			"internal.local": {{IP: net.ParseIP("192.168.1.1")}},
		}},
	}, zerolog.Nop())
	interceptor := NewInterceptor(enforcer, nil, zerolog.Nop())

	if d := interceptor.Decide("https://internal.local/admin"); d != Block {
		t.Errorf("expected Block for private IP target, got %d", d)
	}
}

func TestNeverModifiesURL(t *testing.T) {
	typ := reflect.TypeOf(&Interceptor{})
	forbidden := []string{"SetURL", "ModifyURL", "RewriteURL", "ChangeURL", "ReplaceURL"}
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		for _, f := range forbidden {
			if name == f {
				t.Errorf("Interceptor must not have method %q (allow/block only contract)", name)
			}
		}
	}
}
