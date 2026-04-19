package netutil

import (
	"errors"
	"net"
	"testing"
)

func TestValidateSafeURL_Scheme(t *testing.T) {
	cases := []struct {
		in      string
		wantErr error
	}{
		{"https://example.com/webhook", nil},
		{"http://example.com/webhook", nil},
		{"ftp://example.com/", ErrUnsafeScheme},
		{"file:///etc/passwd", ErrUnsafeScheme},
		{"javascript:alert(1)", ErrUnsafeScheme},
		{"gopher://example.com", ErrUnsafeScheme},
		{"", ErrUnsafeURL},
		{"not a url", ErrUnsafeURL},
		{"https://user:pass@example.com/", ErrUnsafeURL}, // userinfo banned
	}
	for _, c := range cases {
		_, err := ValidateSafeURL(c.in)
		if c.wantErr == nil && err != nil {
			t.Errorf("%q: unexpected err %v", c.in, err)
		}
		if c.wantErr != nil && !errors.Is(err, c.wantErr) {
			t.Errorf("%q: want %v, got %v", c.in, c.wantErr, err)
		}
	}
}

func TestIsSafeAddress(t *testing.T) {
	cases := []struct {
		ip   string
		safe bool
	}{
		// Unsafe: loopback / private / link-local / reserved
		{"127.0.0.1", false},
		{"::1", false},
		{"10.0.0.1", false},
		{"172.16.5.5", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false}, // AWS metadata
		{"fd00::1", false},         // ULA
		{"fe80::1", false},         // link-local
		{"0.0.0.0", false},
		{"::", false},
		{"100.64.1.1", false}, // CGNAT
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		// Safe: public routable
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"93.184.216.34", true},       // example.com
		{"2606:4700:4700::1111", true}, // Cloudflare v6
	}
	for _, c := range cases {
		got := IsSafeAddress(net.ParseIP(c.ip))
		if got != c.safe {
			t.Errorf("%s: got safe=%v, want %v", c.ip, got, c.safe)
		}
	}
}
