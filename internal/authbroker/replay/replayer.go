package replay

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

// Engine drives recorded-login replay through chromedp with hardening checks
// (rate limit, scope/host preflight, circuit breaker, principal binding,
// per-action anomaly detection, and post-state verification).
type Engine struct {
	rateLimit *RateLimit
	circuit   CircuitStore // optional; nil disables circuit checks
}

// NewEngine returns an Engine with default rate limiting and no circuit.
// Callers wire a CircuitStore via WithCircuit when persistence is configured.
func NewEngine() *Engine {
	return &Engine{rateLimit: NewRateLimit()}
}

// WithCircuit attaches a CircuitStore for failure tracking + open-circuit
// short-circuiting. Returns the receiver for chaining.
func (e *Engine) WithCircuit(c CircuitStore) *Engine {
	e.circuit = c
	return e
}

// scanPrincipalKey is the unexported context key under which a scan job's
// expected principal is threaded into Replay.
type scanPrincipalKey struct{}

// ContextWithExpectedPrincipal returns a context carrying the principal that
// the scan job expects the bundle to authenticate as. When set, Replay will
// VerifyPrincipal against the bundle's TargetPrincipal and refuse if they
// disagree.
func ContextWithExpectedPrincipal(parent context.Context, principal string) context.Context {
	return context.WithValue(parent, scanPrincipalKey{}, principal)
}

// Result is what Replay returns to the caller on a successful run.
type Result struct {
	Cookies          []*http.Cookie
	Headers          map[string]string
	FinalURL         string
	BrowserUserAgent string
	StartedAt        time.Time
	StoppedAt        time.Time
}

// Replay walks the bundle's recorded actions inside a fresh chromedp context,
// applying all hardening checks in order. On success it returns the captured
// session cookies bound to the target host.
func (e *Engine) Replay(ctx context.Context, b *bundles.Bundle) (*Result, error) {
	// 1. Existing nil/type/expired/no-actions guards.
	if b == nil {
		return nil, fmt.Errorf("replay: nil bundle")
	}
	if b.Type != "recorded_login" {
		return nil, fmt.Errorf("replay: wrong bundle type %q", b.Type)
	}
	if b.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("replay: bundle expired")
	}
	if len(b.Actions) == 0 {
		return nil, fmt.Errorf("replay: bundle has no recorded actions")
	}

	// 2. Existing target host derivation.
	targetHost := b.TargetHost
	if targetHost == "" && b.RecordingMetadata != nil {
		if u, err := url.Parse(b.RecordingMetadata.FinalURL); err == nil {
			targetHost = u.Host
		}
	}

	// 3. NEW: circuit check (skipped when no store wired).
	if e.circuit != nil {
		bid := mustParseUUID(b.ID)
		open, err := e.circuit.IsOpen(ctx, bid)
		if err != nil {
			return nil, fmt.Errorf("replay: circuit check: %w", err)
		}
		if open {
			return nil, fmt.Errorf("replay: circuit open for bundle %s (refresh_required)", b.ID)
		}
	}

	// 4. Existing rate limit.
	if err := e.rateLimit.Allow(b.ID, targetHost); err != nil {
		return nil, err
	}

	// 5. Existing pre-flight host match.
	if err := preflightHostMatch(b, targetHost); err != nil {
		return nil, err
	}

	// 6. NEW: principal binding (only when a scan-expected principal is set).
	if exp, _ := ctx.Value(scanPrincipalKey{}).(string); exp != "" {
		if err := VerifyPrincipal(b.TargetPrincipal, exp); err != nil {
			return nil, fmt.Errorf("replay: %w", err)
		}
	}

	// 7. NEW: aggregate budget (3x sum of recorded action durations).
	total := 0
	for _, a := range b.Actions {
		total += a.DurationMs
	}
	bctx, cancel := AggregateBudget(ctx, total)
	defer cancel()

	res, err := e.run(bctx, b, targetHost)
	if err != nil {
		return nil, err
	}

	// 9. On overall success: close the circuit (if wired).
	if e.circuit != nil {
		_ = e.circuit.Reset(bctx, mustParseUUID(b.ID))
	}
	return res, nil
}

func preflightHostMatch(b *bundles.Bundle, targetHost string) error {
	if targetHost == "" {
		return fmt.Errorf("replay: target_host unknown")
	}
	for i, a := range b.Actions {
		if a.Kind != bundles.ActionNavigate {
			continue
		}
		u, err := url.Parse(a.URL)
		if err != nil {
			return fmt.Errorf("replay: action %d navigate URL parse: %w", i, err)
		}
		if u.Host == "" {
			continue
		}
		host := strings.TrimPrefix(u.Host, ".")
		target := strings.TrimPrefix(targetHost, ".")
		if host != target {
			return fmt.Errorf("replay: action %d navigates to %q outside target host %q (scope violation)", i, u.Host, targetHost)
		}
	}
	return nil
}

func (e *Engine) run(ctx context.Context, b *bundles.Bundle, targetHost string) (*Result, error) {
	started := time.Now()

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer allocCancel()
	bctx, bcancel := chromedp.NewContext(allocCtx)
	defer bcancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(bctx, 60*time.Second)
	defer timeoutCancel()

	if err := chromedp.Run(timeoutCtx, network.Enable()); err != nil {
		return nil, fmt.Errorf("replay: enable network: %w", err)
	}

	// Hydrate session via existing cookies.
	for _, c := range b.CapturedSession.Cookies {
		cookie := c
		expr := network.SetCookie(cookie.Name, cookie.Value).
			WithDomain(cookie.Domain).WithPath(cookie.Path).
			WithSecure(true).WithHTTPOnly(true)
		if err := chromedp.Run(timeoutCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			return expr.Do(ctx)
		})); err != nil {
			return nil, fmt.Errorf("replay: set cookie %s: %w", cookie.Name, err)
		}
	}

	bundleID := mustParseUUID(b.ID)

	for i, a := range b.Actions {
		actStart := time.Now()
		switch a.Kind {
		case bundles.ActionNavigate:
			if err := chromedp.Run(timeoutCtx, chromedp.Navigate(a.URL)); err != nil {
				return nil, e.recordAndWrap(ctx, bundleID, fmt.Errorf("replay: action %d navigate: %w", i, err))
			}
		case bundles.ActionWaitForLoad:
			// chromedp.Navigate already waits.
		case bundles.ActionCaptchaMark:
			return nil, fmt.Errorf("replay: action %d is captcha_mark — automatable replay not possible", i)
		case bundles.ActionClick:
			// Click capture deferred; treat as no-op.
		}

		// NEW: per-action duration anomaly check.
		if err := CheckActionDuration(time.Since(actStart), a.DurationMs); err != nil {
			return nil, e.recordAndWrap(ctx, bundleID, fmt.Errorf("replay: action %d: %w", i, err))
		}

		// NEW: post-state hash check (skipped when ExpectedPostStateHash is empty).
		if err := VerifyPostState(timeoutCtx, a.ExpectedPostStateHash); err != nil {
			return nil, e.recordAndWrap(ctx, bundleID, fmt.Errorf("replay: action %d: %w", i, err))
		}
	}

	var ua, finalURL string
	cookies, err := fetchAllCookies(allocCtx)
	if err != nil {
		return nil, fmt.Errorf("replay: fetch cookies: %w", err)
	}
	_ = chromedp.Run(allocCtx,
		chromedp.Evaluate(`navigator.userAgent`, &ua),
		chromedp.Evaluate(`window.location.href`, &finalURL),
	)

	httpCookies := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		d := strings.TrimPrefix(c.Domain, ".")
		if d != strings.TrimPrefix(targetHost, ".") {
			continue
		}
		httpCookies = append(httpCookies, &http.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			HttpOnly: c.HTTPOnly, Secure: c.Secure,
		})
	}

	return &Result{
		Cookies:          httpCookies,
		Headers:          make(map[string]string),
		FinalURL:         finalURL,
		BrowserUserAgent: ua,
		StartedAt:        started,
		StoppedAt:        time.Now(),
	}, nil
}

// recordAndWrap records a failure to the circuit (if wired) and returns the
// passed error. Used so the per-action loop stays linear.
func (e *Engine) recordAndWrap(ctx context.Context, bundleID uuid.UUID, err error) error {
	if e.circuit != nil {
		_ = e.circuit.RecordFailure(ctx, bundleID, err.Error())
	}
	return err
}

// mustParseUUID parses s and ignores any error — bundle IDs at this layer are
// already validated upstream. A zero uuid on parse failure is harmless because
// the circuit table would simply have no matching row.
func mustParseUUID(s string) uuid.UUID {
	u, _ := uuid.Parse(s)
	return u
}

func fetchAllCookies(ctx context.Context) ([]*network.Cookie, error) {
	var cookies []*network.Cookie
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		c, err := network.GetCookies().Do(ctx)
		cookies = c
		return err
	}))
	return cookies, err
}
