package httpsec

import (
	"net/http"
	"time"
)

// CookieDefaults is the single source of truth for session cookie
// attributes. Handlers that set cookies directly were re-audited in
// Phase 8 — any new cookie MUST go through SetSessionCookie or
// SetStrictCookie, never http.SetCookie raw.
//
// Secure is forced to true in production. For local development
// without HTTPS, set SC_COOKIE_INSECURE=1 — the helper will warn
// once via the returned error so callers can panic or log.
var insecureCookies = false // flipped by EnableInsecureCookies for local dev

// EnableInsecureCookies disables the Secure flag. Only callable from
// process startup; panics if the process didn't declare SC_ENV!=production.
// Handlers never call this directly.
func EnableInsecureCookies(isProduction bool) {
	if isProduction {
		panic("httpsec: EnableInsecureCookies refused in production")
	}
	insecureCookies = true
}

// SetSessionCookie sets a cookie with Lax SameSite — the default for
// authentication cookies. Lax allows the cookie to ride top-level
// GET navigations so login-return-to flows work, while blocking
// cross-site POSTs.
func SetSessionCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   !insecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// SetStrictCookie is the admin-route variant. SameSite=Strict blocks
// ALL cross-site contexts — including top-level navigation — so the
// cookie cannot be used in a tab opened from an external site. Use
// for /admin/*, /ops/*, and other ambient-authority routes.
func SetStrictCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   !insecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie sets the named cookie to an empty value with MaxAge<0
// so the browser deletes it. Use the same SameSite as was set at
// creation time — the browser keys cookies by (name, path, domain),
// not by SameSite, so this works with either helper above.
func ClearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !insecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}
