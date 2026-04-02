package browser

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// BrowserWorker orchestrates browser-based DAST scans with full security
// hardening. It manages Chrome lifecycle, three-layer scope enforcement,
// and scope-gated auth injection. Crawler logic is NOT implemented here.
type BrowserWorker struct {
	WorkerID string
	broker   *authbroker.Broker
	logger   zerolog.Logger
}

// NewBrowserWorker creates a new browser worker.
func NewBrowserWorker(workerID string, broker *authbroker.Broker, logger zerolog.Logger) *BrowserWorker {
	return &BrowserWorker{
		WorkerID: workerID,
		broker:   broker,
		logger:   logger.With().Str("component", "browser-worker").Str("worker_id", workerID).Logger(),
	}
}

// ExecuteScan runs a browser-based DAST scan.
// Steps:
//  1. Create Chrome context with hardened flags and per-job profile.
//  2. Set up Interceptor (Layer 1) for CDP scope enforcement.
//  3. Set up Monitor (Layer 3) for IP/WebSocket validation.
//  4. Authenticate (if configured) and inject cookies/headers (scope-gated).
//  5. Navigate to target to verify connectivity.
//  6. Collect basic page info.
//  7. Crawler integration placeholder (Phase 5).
//  8. Destroy Chrome, remove profile directory.
//  9. Return BrowserScanResult.
func (bw *BrowserWorker) ExecuteScan(ctx context.Context, job BrowserScanJob) (*BrowserScanResult, error) {
	start := time.Now()
	result := &BrowserScanResult{
		ScanJobID: job.ID,
		WorkerID:  bw.WorkerID,
		Status:    "completed",
		StartedAt: start,
	}

	if job.ID == "" || job.TargetBaseURL == "" {
		result.Status = "failed"
		result.Error = "job ID and target base URL are required"
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, fmt.Errorf("browser/worker: %s", result.Error)
	}

	bw.logger.Info().Str("scan_id", job.ID).Str("target", job.TargetBaseURL).Msg("starting browser scan")

	// Convert pinned IPs from string to net.IP.
	pinnedIPs := make(map[string][]net.IP)
	for host, addrs := range job.PinnedIPs {
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				pinnedIPs[host] = append(pinnedIPs[host], ip)
			}
		}
	}

	// Build scope enforcer.
	scopeCfg := job.ScopeConfig
	if len(scopeCfg.AllowedHosts) == 0 {
		scopeCfg.AllowedHosts = job.AllowedHosts
	}
	if scopeCfg.PinnedIPs == nil {
		scopeCfg.PinnedIPs = pinnedIPs
	}
	enforcer := scope.NewEnforcer(scopeCfg, bw.logger)

	// Step 1: Create Chrome context.
	chromeCtx, chromeCleanup := ChromeContext(ctx, job.ID, bw.logger)
	defer chromeCleanup()

	// Step 2: Authenticate if configured.
	var session *authbroker.Session
	if job.AuthConfig != nil && bw.broker != nil {
		var err error
		session, err = bw.broker.CreateSession(ctx, job.ID, *job.AuthConfig)
		if err != nil {
			bw.logger.Warn().Err(err).Msg("authentication failed, continuing without auth")
		}
	}

	// Step 3: Set up Interceptor (Layer 1).
	interceptor := NewInterceptor(enforcer, session, bw.logger)
	if err := interceptor.Enable(chromeCtx); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("interceptor enable failed: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, fmt.Errorf("browser/worker: %s", result.Error)
	}

	// Step 4: Set up Monitor (Layer 3).
	monitor := NewMonitor(enforcer, bw.logger, 10)
	if err := monitor.Enable(chromeCtx); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("monitor enable failed: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, fmt.Errorf("browser/worker: %s", result.Error)
	}

	// Step 5: Inject cookies (scope-gated) if session has cookies.
	if session != nil && len(session.Cookies) > 0 {
		if err := InjectCookies(chromeCtx, session, job.AllowedHosts); err != nil {
			bw.logger.Warn().Err(err).Msg("cookie injection failed")
		}
	}

	// Step 6: Navigate to target to verify connectivity.
	if err := chromedp.Run(chromeCtx, chromedp.Navigate(job.TargetBaseURL)); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("navigation to target failed: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, fmt.Errorf("browser/worker: %s", result.Error)
	}

	// Step 7: Collect basic page info.
	var title string
	_ = chromedp.Run(chromeCtx, chromedp.Title(&title))
	bw.logger.Info().Str("scan_id", job.ID).Str("page_title", title).Msg("target page loaded")

	// Run crawler
	crawler := NewCrawler(enforcer, bw.logger)
	crawlState := NewCrawlState(job)

	// Seed URLs
	for _, seedURL := range job.SeedURLs {
		crawlState.Enqueue(seedURL, 0)
	}
	// Always seed the target base URL
	crawlState.Enqueue(job.TargetBaseURL, 0)

	pages, crawlErr := crawler.Crawl(ctx, crawlState, chromeCtx)
	if crawlErr != nil {
		bw.logger.Error().Err(crawlErr).Msg("crawler error")
	}

	result.PagesVisited = len(pages)

	// Capture evidence for interesting pages (forms, click interactions, SPA routes).
	for i, page := range pages {
		if page.Error != "" {
			continue
		}
		hasInterestingContent := len(page.Forms) > 0 || len(page.Interactions) > 0
		if !hasInterestingContent {
			continue
		}
		// Navigate back to the page for evidence capture
		if err := chromedp.Run(chromeCtx, chromedp.Navigate(page.URL), chromedp.WaitReady("body")); err != nil {
			bw.logger.Debug().Err(err).Str("url", page.URL).Msg("evidence nav failed")
			continue
		}
		ev, err := CapturePageEvidence(ctx, chromeCtx, page.URL, job.ID, true)
		if err == nil {
			pages[i].Evidence = ev
		}
		bw.logger.Info().
			Str("url", page.URL).
			Int("forms", len(page.Forms)).
			Int("click_targets", len(page.ClickTargets)).
			Int("interactions", len(page.Interactions)).
			Msg("page evidence captured")
	}

	// Collect violation counts.
	result.ScopeViolations = interceptor.Violations() + monitor.Violations()

	if monitor.IsAborted() {
		result.Status = "aborted"
		result.Error = "scan aborted: Layer 3 violation threshold exceeded"
	}

	// Chrome cleanup is handled by deferred chromeCleanup().
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	bw.logger.Info().
		Str("scan_id", job.ID).
		Str("status", result.Status).
		Int64("scope_violations", result.ScopeViolations).
		Dur("duration", result.Duration).
		Msg("browser scan completed")

	return result, nil
}
