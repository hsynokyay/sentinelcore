// Package recording provides a chromedp-based browser recorder for DAST
// authenticated scans. Customers run it locally to capture a logged-in
// session jar (cookies + final URL + UA fingerprint) for an application
// protected by CAPTCHA or MFA. The recorder does NOT store form-fill
// values — credentials remain in the user's head; only the resulting
// session is captured.
package recording

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

// RecordedSession captures the state of a logged-in browser session at the
// moment recording stopped.
type RecordedSession struct {
	Cookies          []*http.Cookie
	Headers          map[string]string
	FinalURL         string
	BrowserUserAgent string
	StartedAt        time.Time
	StoppedAt        time.Time
	CaptchaDetected  bool
	Actions          []bundles.Action
}

// Options control recording behavior.
type Options struct {
	TargetURL        string
	AllowedHosts     []string
	HeadlessFallback bool
	StopWhenURL      string
	Timeout          time.Duration
}

// Recorder owns the chromedp browser context and event subscriptions.
type Recorder struct {
	opts            Options
	capturedHeaders map[string]string
	captchaDetected bool
	startedAt       time.Time
	actionsMu       sync.Mutex
	actions         []bundles.Action
}

// recordAction appends a to the recorder's action list in a thread-safe manner.
func (r *Recorder) recordAction(a bundles.Action) {
	r.actionsMu.Lock()
	defer r.actionsMu.Unlock()
	r.actions = append(r.actions, a)
}

// New returns a Recorder ready to Run.
func New(opts Options) *Recorder {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Minute
	}
	return &Recorder{
		opts:            opts,
		capturedHeaders: make(map[string]string),
	}
}

// Run launches Chrome, navigates to TargetURL, and blocks until the user
// signals stop via context cancellation OR the timeout/StopWhenURL fires.
// Returns the captured session.
func (r *Recorder) Run(ctx context.Context) (*RecordedSession, error) {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", r.opts.HeadlessFallback),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-features", "Autofill,FillingAcrossAffiliations,ChromeCleanup,NetworkService,SafeBrowsingEnhancedProtection"),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer allocCancel()

	bctx, bcancel := chromedp.NewContext(allocCtx)
	defer bcancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(bctx, r.opts.Timeout)
	defer timeoutCancel()

	r.startedAt = time.Now()

	chromedp.ListenTarget(timeoutCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			r.captureHeaders(e.Response)
			if r.opts.StopWhenURL != "" && strings.HasPrefix(e.Response.URL, r.opts.StopWhenURL) {
				bcancel()
			}
		case *page.EventFrameNavigated:
			if e.Frame != nil && e.Frame.URL != "" {
				r.recordAction(bundles.Action{
					Kind:      bundles.ActionNavigate,
					URL:       e.Frame.URL,
					Timestamp: time.Now().UTC(),
				})
			}
		}
	})

	if err := chromedp.Run(timeoutCtx,
		network.Enable(),
		chromedp.Navigate(r.opts.TargetURL),
	); err != nil {
		return nil, fmt.Errorf("recording: initial navigate: %w", err)
	}

	<-timeoutCtx.Done()

	var ua, finalURL string
	cookies, err := r.fetchCookies(allocCtx)
	if err != nil {
		return nil, fmt.Errorf("recording: fetch cookies: %w", err)
	}
	_ = chromedp.Run(allocCtx,
		chromedp.Evaluate(`navigator.userAgent`, &ua),
		chromedp.Evaluate(`window.location.href`, &finalURL),
	)

	httpCookies := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if !hostAllowed(c.Domain, r.opts.AllowedHosts) {
			continue
		}
		httpCookies = append(httpCookies, &http.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			HttpOnly: c.HTTPOnly, Secure: c.Secure,
		})
	}

	return &RecordedSession{
		Cookies:          httpCookies,
		Headers:          r.capturedHeaders,
		FinalURL:         finalURL,
		BrowserUserAgent: ua,
		StartedAt:        r.startedAt,
		StoppedAt:        time.Now(),
		CaptchaDetected:  r.captchaDetected,
		Actions:          r.actions,
	}, nil
}

func (r *Recorder) fetchCookies(ctx context.Context) ([]*network.Cookie, error) {
	var cookies []*network.Cookie
	err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			c, err := network.GetCookies().Do(ctx)
			cookies = c
			return err
		}),
	)
	return cookies, err
}

func (r *Recorder) captureHeaders(resp *network.Response) {
	if resp == nil {
		return
	}
	for k, v := range resp.Headers {
		if k == "Authentication-Info" {
			r.capturedHeaders[k] = fmt.Sprint(v)
		}
	}
	captchaMarkers := []string{"google.com/recaptcha", "hcaptcha.com", "challenges.cloudflare.com"}
	for _, marker := range captchaMarkers {
		if strings.Contains(resp.URL, marker) {
			r.captchaDetected = true
			r.recordAction(bundles.Action{Kind: bundles.ActionCaptchaMark, Timestamp: time.Now().UTC()})
			break
		}
	}
}

func hostAllowed(domain string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	domain = strings.TrimPrefix(domain, ".")
	for _, h := range allowed {
		if domain == h {
			return true
		}
	}
	return false
}
