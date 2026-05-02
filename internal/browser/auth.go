package browser

import (
	"context"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// ShouldInjectAuth returns true only if the request URL is within scope
// according to the enforcer. Used to gate auth credential injection.
func ShouldInjectAuth(reqURL string, enforcer *scope.Enforcer) bool {
	return enforcer.CheckRequest(context.Background(), reqURL) == nil
}

// InjectCookies sets session cookies via CDP Network.setCookie. Each cookie's
// domain is validated against the allowed hosts — third-party cookies are skipped.
// All cookies are hardened with SameSite=Strict, HttpOnly=true, Secure=true.
func InjectCookies(ctx context.Context, session *authbroker.Session, allowedHosts []string) error {
	if session == nil {
		return fmt.Errorf("browser/auth: session is nil")
	}

	for _, c := range session.Cookies {
		if c == nil {
			continue
		}

		domain := strings.TrimPrefix(c.Domain, ".")
		if !isDomainAllowed(domain, allowedHosts) {
			continue
		}

		cookieDomain := c.Domain
		if cookieDomain == "" {
			cookieDomain = domain
		}

		expr := network.SetCookie(c.Name, c.Value).
			WithDomain(cookieDomain).
			WithPath(c.Path).
			WithSecure(true).
			WithHTTPOnly(true).
			WithSameSite(network.CookieSameSiteStrict)

		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			return expr.Do(ctx)
		})); err != nil {
			return fmt.Errorf("browser/auth: failed to set cookie %q: %w", c.Name, err)
		}
	}

	return nil
}

// isDomainAllowed returns true if cookieDomain exactly matches or is a subdomain
// of one of the allowed hosts.
func isDomainAllowed(cookieDomain string, allowedHosts []string) bool {
	cookieDomain = strings.ToLower(strings.TrimPrefix(cookieDomain, "."))
	for _, host := range allowedHosts {
		host = strings.ToLower(host)
		if cookieDomain == host || strings.HasSuffix(cookieDomain, "."+host) {
			return true
		}
	}
	return false
}
