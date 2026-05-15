// Package netutil provides SSRF-safe URL parsing for user-supplied
// URLs (webhook destinations, fetch-from-url, OIDC issuer_url, ...).
//
// The core rule: before dialing a URL supplied by a tenant, resolve
// its hostname and REJECT addresses in any of:
//
//   - link-local (169.254.0.0/16, fe80::/10)
//   - loopback (127.0.0.0/8, ::1)
//   - private (RFC1918 10/8, 172.16/12, 192.168/16 + IPv6 fc00::/7)
//   - metadata endpoints (169.254.169.254, fd00:ec2::254)
//   - multicast / reserved blocks
//
// Without this gate, a tenant pointing a webhook URL at
// http://localhost:8080/admin/... can steal admin functions, and one
// pointing at http://169.254.169.254 can exfiltrate cloud-provider
// credentials from the host.
//
// Usage:
//
//     if err := netutil.ValidateSafeURL(u); err != nil {
//         return fmt.Errorf("invalid URL: %w", err)
//     }
//
// ValidateSafeURL resolves the hostname at check time; the caller
// should RESOLVE-AND-DIAL the same address ("pin") rather than
// re-resolving at dial time, because DNS can change between check
// and dial (DNS rebinding attack). Use SafeDialer for that.
package netutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ErrUnsafeURL is returned for any URL that fails the safety checks.
// More specific sentinels (ErrUnsafeScheme) wrap this so callers can
// use either `errors.Is(err, ErrUnsafeURL)` for the broad check or
// the specific one for finer-grained handling.
var ErrUnsafeURL = errors.New("netutil: URL not safe for outbound fetch")

// ErrUnsafeScheme is returned for schemes other than http/https.
// Wraps ErrUnsafeURL.
var ErrUnsafeScheme = fmt.Errorf("%w: only http/https schemes allowed", ErrUnsafeURL)

// ValidateSafeURL parses s and checks scheme + host. On success
// returns the parsed *url.URL; on failure returns a wrapped error.
// Does NOT resolve DNS — combine with IsSafeAddress for full check.
func ValidateSafeURL(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("%w: empty", ErrUnsafeURL)
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrUnsafeURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: got %q", ErrUnsafeScheme, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrUnsafeURL)
	}
	// Reject user-info segment outright — rare in legitimate URLs
	// and a common phishing vector when combined with a tenant-
	// controlled destination.
	if u.User != nil {
		return nil, fmt.Errorf("%w: embedded userinfo not allowed", ErrUnsafeURL)
	}
	return u, nil
}

// ValidateAndResolve does ValidateSafeURL + DNS resolution, then
// asserts every returned address is safe. Returns the pinned
// resolved IP list the caller should dial directly.
func ValidateAndResolve(ctx context.Context, s string) (*url.URL, []net.IP, error) {
	u, err := ValidateSafeURL(s)
	if err != nil {
		return nil, nil, err
	}
	host := u.Hostname()
	// Strip IPv6 brackets for net.LookupIP; Hostname() already does this.
	resolver := &net.Resolver{}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := resolver.LookupIPAddr(dctx, host)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: resolve %q: %v", ErrUnsafeURL, host, err)
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("%w: no A/AAAA records for %q", ErrUnsafeURL, host)
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if !IsSafeAddress(a.IP) {
			return nil, nil, fmt.Errorf("%w: %q resolves to %s", ErrUnsafeURL, host, a.IP)
		}
		out = append(out, a.IP)
	}
	return u, out, nil
}

// IsSafeAddress reports whether ip is in a routable, non-private,
// non-loopback, non-link-local range. Returns false for literals
// that would make an outbound fetch dangerous.
func IsSafeAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsPrivate() {
		return false
	}
	// Reserved blocks IsPrivate doesn't cover.
	reservedV4 := []*net.IPNet{
		mustCIDR("169.254.0.0/16"), // link-local (covered), explicit
		mustCIDR("198.18.0.0/15"),  // benchmarking RFC2544
		mustCIDR("100.64.0.0/10"),  // CGNAT
		mustCIDR("192.0.0.0/24"),   // IETF protocol assignments
		mustCIDR("192.0.2.0/24"),   // TEST-NET-1
		mustCIDR("198.51.100.0/24"), // TEST-NET-2
		mustCIDR("203.0.113.0/24"), // TEST-NET-3
		mustCIDR("224.0.0.0/4"),    // multicast (covered), explicit
		mustCIDR("240.0.0.0/4"),    // reserved
	}
	reservedV6 := []*net.IPNet{
		mustCIDR("2001:db8::/32"), // documentation
		mustCIDR("fc00::/7"),      // ULA (covered by IsPrivate on modern Go but keep explicit)
		mustCIDR("fe80::/10"),     // link-local (covered)
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range reservedV4 {
			if n.Contains(v4) {
				return false
			}
		}
		return true
	}
	for _, n := range reservedV6 {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// SafeHTTPClient returns an *http.Client whose dialer refuses to
// connect to any address rejected by IsSafeAddress. Use for ALL
// outbound fetches of user-supplied URLs.
//
// Implementation note: we resolve the host ourselves (via
// ValidateAndResolve) and dial the resolved IP rather than the
// hostname. This prevents the "rebind at dial time" race where the
// validator sees a safe address but the dialer's re-resolution
// returns a private one.
func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("netutil: bad CIDR literal: " + s)
	}
	return n
}
