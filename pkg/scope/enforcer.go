// Package scope implements multi-layer DAST scope enforcement to prevent
// scan workers from accessing targets outside the authorized scan perimeter.
package scope

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// blockedCIDRs contains RFC 1918, loopback, link-local, and cloud metadata ranges.
var blockedCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"0.0.0.0/8",
		"240.0.0.0/4",
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("scope: invalid blocked CIDR %q: %v", cidr, err))
		}
		blockedCIDRs = append(blockedCIDRs, ipNet)
	}
}

// Violation records a scope enforcement failure.
type Violation struct {
	Type      string    `json:"type"`
	Detail    string    `json:"detail"`
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`
}

// Config controls Enforcer behavior.
type Config struct {
	// AllowedHosts is the set of hostnames the scan may contact.
	AllowedHosts []string

	// PinnedIPs maps hostname → set of allowed IPs resolved at scan start.
	// If nil, the enforcer resolves and pins on first call to PinHosts.
	PinnedIPs map[string][]net.IP

	// MaxViolations triggers automatic scan abort when reached. 0 = no limit.
	MaxViolations int

	// AllowPrivateIPs overrides the internal-IP blocklist (for testing only).
	AllowPrivateIPs bool

	// MaxRedirects limits redirect chain depth. Default 10.
	MaxRedirects int

	// Resolver overrides the DNS resolver (for testing).
	Resolver Resolver
}

// Resolver abstracts DNS resolution for testing.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type defaultResolver struct{}

func (d *defaultResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// Enforcer validates every DAST request against the authorized scope.
type Enforcer struct {
	mu             sync.RWMutex
	allowedHosts   map[string]bool
	pinnedIPs      map[string][]net.IP
	violations     []Violation
	violationCount atomic.Int64
	maxViolations  int
	allowPrivate   bool
	maxRedirects   int
	resolver       Resolver
	logger         zerolog.Logger
	aborted        atomic.Bool
}

// NewEnforcer creates a scope enforcer from the given config.
func NewEnforcer(cfg Config, logger zerolog.Logger) *Enforcer {
	hosts := make(map[string]bool, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		hosts[strings.ToLower(h)] = true
	}

	maxRedirects := cfg.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}

	resolver := cfg.Resolver
	if resolver == nil {
		resolver = &defaultResolver{}
	}

	e := &Enforcer{
		allowedHosts:  hosts,
		pinnedIPs:     make(map[string][]net.IP),
		maxViolations: cfg.MaxViolations,
		allowPrivate:  cfg.AllowPrivateIPs,
		maxRedirects:  maxRedirects,
		resolver:      resolver,
		logger:        logger.With().Str("component", "scope-enforcer").Logger(),
	}

	if cfg.PinnedIPs != nil {
		for host, ips := range cfg.PinnedIPs {
			e.pinnedIPs[strings.ToLower(host)] = ips
		}
	}

	return e
}

// PinHosts resolves and pins IPs for all allowed hosts.
// Must be called before scan starts. Returns error if any host
// resolves to a blocked IP.
func (e *Enforcer) PinHosts(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for host := range e.allowedHosts {
		addrs, err := e.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return fmt.Errorf("scope: failed to resolve %q: %w", host, err)
		}

		var ips []net.IP
		for _, addr := range addrs {
			if !e.allowPrivate && isBlockedIP(addr.IP) {
				return fmt.Errorf("scope: host %q resolves to blocked IP %s", host, addr.IP)
			}
			ips = append(ips, addr.IP)
		}

		if len(ips) == 0 {
			return fmt.Errorf("scope: host %q has no valid IPs", host)
		}

		e.pinnedIPs[host] = ips
		e.logger.Info().Str("host", host).Int("ip_count", len(ips)).Msg("pinned host IPs")
	}

	return nil
}

// CheckRequest validates that a request URL is within scope.
// Returns nil if allowed, error describing the violation otherwise.
func (e *Enforcer) CheckRequest(ctx context.Context, reqURL string) error {
	if e.aborted.Load() {
		return fmt.Errorf("scope: scan aborted due to excessive violations")
	}

	parsed, err := url.Parse(reqURL)
	if err != nil {
		e.recordViolation("invalid_url", err.Error(), reqURL)
		return fmt.Errorf("scope: invalid URL: %w", err)
	}

	// Scheme check
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		e.recordViolation("invalid_scheme", scheme, reqURL)
		return fmt.Errorf("scope: scheme %q not allowed", scheme)
	}

	// Host check
	hostname := strings.ToLower(parsed.Hostname())
	if !e.isAllowedHost(hostname) {
		e.recordViolation("host_not_allowed", hostname, reqURL)
		return fmt.Errorf("scope: host %q not in allowed set", hostname)
	}

	// DNS rebinding check: re-resolve and compare against pinned set
	addrs, err := e.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		e.recordViolation("dns_resolution_failed", err.Error(), reqURL)
		return fmt.Errorf("scope: DNS resolution failed for %q: %w", hostname, err)
	}

	for _, addr := range addrs {
		if !e.allowPrivate && isBlockedIP(addr.IP) {
			e.recordViolation("blocked_ip", addr.IP.String(), reqURL)
			return fmt.Errorf("scope: %q resolves to blocked IP %s", hostname, addr.IP)
		}
		if !e.isPinnedIP(hostname, addr.IP) {
			e.recordViolation("dns_rebinding", fmt.Sprintf("%s resolved to unpinned IP %s", hostname, addr.IP), reqURL)
			return fmt.Errorf("scope: DNS rebinding detected — %q resolved to unpinned IP %s", hostname, addr.IP)
		}
	}

	return nil
}

// CheckRedirect validates a redirect target. Same as CheckRequest but also
// enforces redirect chain depth via the provided count.
func (e *Enforcer) CheckRedirect(ctx context.Context, redirectURL string, redirectCount int) error {
	if redirectCount >= e.maxRedirects {
		e.recordViolation("max_redirects", fmt.Sprintf("exceeded %d redirects", e.maxRedirects), redirectURL)
		return fmt.Errorf("scope: redirect chain exceeded maximum of %d", e.maxRedirects)
	}
	return e.CheckRequest(ctx, redirectURL)
}

// Violations returns all recorded violations.
func (e *Enforcer) Violations() []Violation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Violation, len(e.violations))
	copy(out, e.violations)
	return out
}

// ViolationCount returns the total number of violations.
func (e *Enforcer) ViolationCount() int64 {
	return e.violationCount.Load()
}

// IsAborted returns true if the enforcer triggered automatic scan abort.
func (e *Enforcer) IsAborted() bool {
	return e.aborted.Load()
}

// PinnedIPs returns the pinned IP set for a host.
func (e *Enforcer) PinnedIPs(host string) []net.IP {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.pinnedIPs[strings.ToLower(host)]
}

func (e *Enforcer) isAllowedHost(hostname string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.allowedHosts[hostname]
}

func (e *Enforcer) isPinnedIP(host string, ip net.IP) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	pinned, ok := e.pinnedIPs[strings.ToLower(host)]
	if !ok {
		return false
	}
	for _, p := range pinned {
		if p.Equal(ip) {
			return true
		}
	}
	return false
}

func (e *Enforcer) recordViolation(vtype, detail, reqURL string) {
	v := Violation{
		Type:      vtype,
		Detail:    detail,
		URL:       reqURL,
		Timestamp: time.Now(),
	}

	e.mu.Lock()
	e.violations = append(e.violations, v)
	e.mu.Unlock()

	count := e.violationCount.Add(1)
	e.logger.Warn().
		Str("type", vtype).
		Str("detail", detail).
		Str("url", reqURL).
		Int64("total_violations", count).
		Msg("scope violation")

	if e.maxViolations > 0 && int(count) >= e.maxViolations {
		e.aborted.Store(true)
		e.logger.Error().Int64("violations", count).Msg("scan aborted: max violations exceeded")
	}
}

// isBlockedIP checks if an IP falls within any blocked CIDR range.
func isBlockedIP(ip net.IP) bool {
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBlockedIP is the exported version for use by other packages.
func IsBlockedIP(ip net.IP) bool {
	return isBlockedIP(ip)
}

// ScopedTransport wraps an http.RoundTripper to enforce scope on every request.
type ScopedTransport struct {
	Enforcer  *Enforcer
	Transport http.RoundTripper
	redirects int
}

// RoundTrip implements http.RoundTripper with scope enforcement.
func (t *ScopedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.Enforcer.CheckRequest(req.Context(), req.URL.String()); err != nil {
		return nil, err
	}
	if t.Transport == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return t.Transport.RoundTrip(req)
}

// NewScopedClient creates an http.Client that enforces scope on every request
// and validates redirects.
func NewScopedClient(enforcer *Enforcer, timeout time.Duration) *http.Client {
	transport := &ScopedTransport{
		Enforcer:  enforcer,
		Transport: http.DefaultTransport,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return enforcer.CheckRedirect(req.Context(), req.URL.String(), len(via))
		},
	}
}
