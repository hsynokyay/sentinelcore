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

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

type Engine struct {
	rateLimit *RateLimit
}

func NewEngine() *Engine {
	return &Engine{rateLimit: NewRateLimit()}
}

type Result struct {
	Cookies          []*http.Cookie
	Headers          map[string]string
	FinalURL         string
	BrowserUserAgent string
	StartedAt        time.Time
	StoppedAt        time.Time
}

func (e *Engine) Replay(ctx context.Context, b *bundles.Bundle) (*Result, error) {
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

	targetHost := b.TargetHost
	if targetHost == "" && b.RecordingMetadata != nil {
		if u, err := url.Parse(b.RecordingMetadata.FinalURL); err == nil {
			targetHost = u.Host
		}
	}

	if err := e.rateLimit.Allow(b.ID, targetHost); err != nil {
		return nil, err
	}

	if err := preflightHostMatch(b, targetHost); err != nil {
		return nil, err
	}

	return e.run(ctx, b, targetHost)
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

	for i, a := range b.Actions {
		switch a.Kind {
		case bundles.ActionNavigate:
			if err := chromedp.Run(timeoutCtx, chromedp.Navigate(a.URL)); err != nil {
				return nil, fmt.Errorf("replay: action %d navigate: %w", i, err)
			}
		case bundles.ActionWaitForLoad:
			// chromedp.Navigate already waits.
		case bundles.ActionCaptchaMark:
			return nil, fmt.Errorf("replay: action %d is captcha_mark — automatable replay not possible", i)
		case bundles.ActionClick:
			// Click capture deferred; treat as no-op.
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

func fetchAllCookies(ctx context.Context) ([]*network.Cookie, error) {
	var cookies []*network.Cookie
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		c, err := network.GetCookies().Do(ctx)
		cookies = c
		return err
	}))
	return cookies, err
}
