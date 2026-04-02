package browser

import (
	"context"
	"sync/atomic"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// Decision represents an allow/block verdict for a CDP request.
type Decision int

const (
	// Allow permits the request to proceed.
	Allow Decision = iota
	// Block denies the request.
	Block
)

// Interceptor implements Layer 1 CDP Fetch.requestPaused scope enforcement.
// It is strictly allow/block — it has NO methods to modify request URLs or bodies.
type Interceptor struct {
	enforcer   *scope.Enforcer
	session    *authbroker.Session
	logger     zerolog.Logger
	violations atomic.Int64
}

// NewInterceptor creates a CDP request interceptor with the given scope enforcer
// and optional auth session for header injection on allowed requests.
func NewInterceptor(enforcer *scope.Enforcer, session *authbroker.Session, logger zerolog.Logger) *Interceptor {
	return &Interceptor{
		enforcer: enforcer,
		session:  session,
		logger:   logger.With().Str("component", "cdp-interceptor").Logger(),
	}
}

// Decide checks whether the given request URL is in scope.
// Returns Allow if the URL passes scope enforcement, Block otherwise.
// Increments the violation counter on Block.
func (i *Interceptor) Decide(reqURL string) Decision {
	if err := i.enforcer.CheckRequest(context.Background(), reqURL); err != nil {
		i.violations.Add(1)
		i.logger.Warn().Str("url", reqURL).Err(err).Msg("blocked out-of-scope request")
		return Block
	}
	return Allow
}

// Violations returns the total number of blocked requests.
func (i *Interceptor) Violations() int64 {
	return i.violations.Load()
}

// Enable sets up the Fetch.requestPaused CDP event handler with a wildcard
// pattern that intercepts all network requests.
func (i *Interceptor) Enable(ctx context.Context) error {
	// Enable Fetch domain with wildcard pattern to intercept all requests.
	if err := fetch.Enable().WithPatterns([]*fetch.RequestPattern{
		{URLPattern: "*", RequestStage: fetch.RequestStageRequest},
	}).Do(ctx); err != nil {
		return err
	}

	// Register the event listener for paused requests.
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if e, ok := ev.(*fetch.EventRequestPaused); ok {
			go i.handleRequestPaused(ctx, e)
		}
	})

	i.logger.Info().Msg("CDP interceptor enabled with wildcard pattern")
	return nil
}

// handleRequestPaused processes a paused request: block out-of-scope requests,
// allow in-scope requests with optional auth header injection.
// NEVER modifies the request URL.
func (i *Interceptor) handleRequestPaused(ctx context.Context, ev *fetch.EventRequestPaused) {
	reqURL := ev.Request.URL
	decision := i.Decide(reqURL)

	if decision == Block {
		_ = fetch.FailRequest(ev.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
		return
	}

	// Allow — optionally inject auth headers for in-scope requests.
	if i.session != nil && len(i.session.Headers) > 0 {
		var headers []*fetch.HeaderEntry
		// Preserve existing request headers.
		for k, v := range ev.Request.Headers {
			if vs, ok := v.(string); ok {
				headers = append(headers, &fetch.HeaderEntry{Name: k, Value: vs})
			}
		}
		// Inject session auth headers.
		for k, v := range i.session.Headers {
			headers = append(headers, &fetch.HeaderEntry{Name: k, Value: v})
		}
		_ = fetch.ContinueRequest(ev.RequestID).WithHeaders(headers).Do(ctx)
		return
	}

	// Allow with no header modification.
	_ = fetch.ContinueRequest(ev.RequestID).Do(ctx)
}
