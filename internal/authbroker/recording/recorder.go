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
	"github.com/chromedp/cdproto/runtime"
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

// recordAction appends a to the recorder's action list in a thread-safe
// manner and back-fills DurationMs on the previous action using the gap
// between consecutive timestamps.
func (r *Recorder) recordAction(a bundles.Action) {
	r.actionsMu.Lock()
	defer r.actionsMu.Unlock()
	if n := len(r.actions); n > 0 {
		prev := r.actions[n-1]
		gap := a.Timestamp.Sub(prev.Timestamp).Milliseconds()
		if gap < 0 {
			gap = 0
		}
		r.actions[n-1].DurationMs = int(gap)
	}
	r.actions = append(r.actions, a)
}

// setLastActionHash assigns hash to the tail action only if the tail's
// timestamp still matches forTS — i.e. no newer action has arrived since
// the hash compute was kicked off. This is the late-assign safety check
// for the goroutine path (see asyncCapturePostStateHash).
func (r *Recorder) setLastActionHash(forTS time.Time, hash string) {
	if hash == "" {
		return
	}
	r.actionsMu.Lock()
	defer r.actionsMu.Unlock()
	n := len(r.actions)
	if n == 0 {
		return
	}
	if !r.actions[n-1].Timestamp.Equal(forTS) {
		return
	}
	r.actions[n-1].ExpectedPostStateHash = hash
}

// asyncCapturePostStateHash fires ComputePostStateHash on a goroutine and
// late-assigns the result to the tail action if it is still the tail.
// We dispatch off the ListenTarget callback because chromedp.Run is
// synchronous on the same target and would deadlock if invoked from inside
// an event handler.
func (r *Recorder) asyncCapturePostStateHash(ctx context.Context, forTS time.Time) {
	go func() {
		hash, err := ComputePostStateHash(ctx)
		if err != nil {
			return // best-effort: leave hash empty on transient failure
		}
		r.setLastActionHash(forTS, hash)
	}()
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
				ts := time.Now().UTC()
				r.recordAction(bundles.Action{
					Kind:      bundles.ActionNavigate,
					URL:       e.Frame.URL,
					Timestamp: ts,
				})
				r.asyncCapturePostStateHash(timeoutCtx, ts)
			}
		case *runtime.EventBindingCalled:
			if e.Name != "__sentinel_emit" {
				return
			}
			a, err := ParseAndValidate(e.Payload)
			if err != nil {
				// Drop invalid events — they are not fatal.
				return
			}
			r.recordAction(a)
			r.asyncCapturePostStateHash(timeoutCtx, a.Timestamp)
		}
	})

	if err := chromedp.Run(timeoutCtx,
		network.Enable(),
		chromedp.ActionFunc(func(c context.Context) error {
			if err := runtime.AddBinding("__sentinel_emit").Do(c); err != nil {
				return fmt.Errorf("recording: add binding: %w", err)
			}
			if _, err := page.AddScriptToEvaluateOnNewDocument(captureScript).Do(c); err != nil {
				return fmt.Errorf("recording: install capture script: %w", err)
			}
			return nil
		}),
		chromedp.Navigate(r.opts.TargetURL),
	); err != nil {
		return nil, fmt.Errorf("recording: initial navigate: %w", err)
	}

	<-timeoutCtx.Done()

	// Final action has no successor to back-fill its DurationMs from, so
	// stamp it from the time elapsed since its own timestamp.
	r.actionsMu.Lock()
	if n := len(r.actions); n > 0 {
		last := r.actions[n-1]
		dur := time.Since(last.Timestamp).Milliseconds()
		if dur < 0 {
			dur = 0
		}
		r.actions[n-1].DurationMs = int(dur)
	}
	r.actionsMu.Unlock()

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
