// Package httpsec provides the outermost HTTP security middleware
// chain for SentinelCore services: request size cap, response
// hardening headers, HSTS, and the step-up-reauth gate.
//
// Intended usage from server.go:
//
//     handler = httpsec.Chain(handler, httpsec.Defaults()...)
//
// Order of wrapping matters: headers are written AFTER the handler
// runs. Chain sets them before delegating to the next handler so
// they land on the response regardless of how the handler writes.
package httpsec

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Option is a functional option for Chain.
type Option func(*config)

type config struct {
	maxBodySize        int64
	hsts               bool
	hstsMaxAgeSeconds  int
	hstsIncludeSubs    bool
	noSniff            bool
	frameDeny          bool
	referrerPolicy     string
	permissionsPolicy  string
	uploadPathPrefixes []string
	uploadMaxBodySize  int64
}

// WithMaxBodySize caps request bodies. Defaults to 1 MiB.
// Requests exceeding the cap surface http.MaxBytesError from
// r.Body.Read() — use IsBodyTooLarge to distinguish from other
// decode errors in handlers.
func WithMaxBodySize(n int64) Option {
	return func(c *config) { c.maxBodySize = n }
}

// WithUploadException grants a larger body-size cap to paths whose
// URL.Path starts with any of the given prefixes. Typical use:
// WithUploadException(10<<20, "/api/v1/source-artifacts/").
func WithUploadException(maxSize int64, prefixes ...string) Option {
	return func(c *config) {
		c.uploadMaxBodySize = maxSize
		c.uploadPathPrefixes = append(c.uploadPathPrefixes, prefixes...)
	}
}

// WithHSTS enables Strict-Transport-Security with a 1-year max-age
// and includeSubDomains. Browsers honour the directive only for
// HTTPS responses, so dev HTTP is unaffected.
func WithHSTS() Option {
	return func(c *config) {
		c.hsts = true
		c.hstsMaxAgeSeconds = 31536000
		c.hstsIncludeSubs = true
	}
}

// WithNoSniff sets X-Content-Type-Options: nosniff.
func WithNoSniff() Option { return func(c *config) { c.noSniff = true } }

// WithFrameDeny sets X-Frame-Options: DENY.
func WithFrameDeny() Option { return func(c *config) { c.frameDeny = true } }

// WithReferrerPolicy sets the Referrer-Policy header.
// Recommended: "strict-origin-when-cross-origin".
func WithReferrerPolicy(policy string) Option {
	return func(c *config) { c.referrerPolicy = policy }
}

// WithPermissionsPolicy sets Permissions-Policy (formerly
// Feature-Policy). Use to deny camera, microphone, etc. API-wide.
func WithPermissionsPolicy(policy string) Option {
	return func(c *config) { c.permissionsPolicy = policy }
}

// Defaults is the production-safe bundle: 1 MiB body, HSTS 1y incl.
// subdomains, nosniff, frame-deny, strict-origin referrer, and a
// locked-down permissions policy.
func Defaults() []Option {
	return []Option{
		WithMaxBodySize(1 << 20),
		WithHSTS(),
		WithNoSniff(),
		WithFrameDeny(),
		WithReferrerPolicy("strict-origin-when-cross-origin"),
		WithPermissionsPolicy(
			"camera=(), microphone=(), geolocation=(), " +
				"payment=(), usb=(), fullscreen=(self)"),
	}
}

// Chain wraps h with every enabled security option.
func Chain(h http.Handler, opts ...Option) http.Handler {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Cap body size. Two-tier so upload endpoints can
		//    exceed the default without letting the general API.
		if cfg.maxBodySize > 0 {
			max := cfg.maxBodySize
			if cfg.uploadMaxBodySize > 0 && pathMatches(r.URL.Path, cfg.uploadPathPrefixes) {
				max = cfg.uploadMaxBodySize
			}
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
		// 2. Set security response headers. Set before delegate so
		//    handlers that stream / early-write still carry them.
		setResponseHeaders(w, cfg)
		// 3. Delegate.
		h.ServeHTTP(w, r)
	})
}

func setResponseHeaders(w http.ResponseWriter, c *config) {
	h := w.Header()
	if c.hsts {
		v := fmt.Sprintf("max-age=%d", c.hstsMaxAgeSeconds)
		if c.hstsIncludeSubs {
			v += "; includeSubDomains"
		}
		h.Set("Strict-Transport-Security", v)
	}
	if c.noSniff {
		h.Set("X-Content-Type-Options", "nosniff")
	}
	if c.frameDeny {
		h.Set("X-Frame-Options", "DENY")
	}
	if c.referrerPolicy != "" {
		h.Set("Referrer-Policy", c.referrerPolicy)
	}
	if c.permissionsPolicy != "" {
		h.Set("Permissions-Policy", c.permissionsPolicy)
	}
}

func pathMatches(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// IsBodyTooLarge reports whether err originated from the request
// size cap (http.MaxBytesError). Safe to call on any error. Use in
// handlers to surface 413 cleanly:
//
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         if httpsec.IsBodyTooLarge(err) {
//             writeError(w, 413, "body too large", "PAYLOAD_TOO_LARGE")
//             return
//         }
//         writeError(w, 400, "invalid body", "BAD_REQUEST")
//         return
//     }
func IsBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}
