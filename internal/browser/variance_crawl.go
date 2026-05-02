package browser

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// RunAnonymousCrawl performs a reduced-budget crawl without authentication.
// Uses the same scope enforcer and Chrome context but without auth injection.
// Returns a CrawlSnapshot for comparison with the authenticated crawl.
func RunAnonymousCrawl(ctx context.Context, job BrowserScanJob, enforcer *scope.Enforcer, logger zerolog.Logger) (*CrawlSnapshot, error) {
	// Create a fresh Chrome context for anonymous crawl (no auth cookies/headers).
	chromeCtx, cleanup := ChromeContext(ctx, job.ID+"-anon", logger)
	defer cleanup()

	// Set up interceptor WITHOUT session (no auth injection).
	interceptor := NewInterceptor(enforcer, nil, logger)
	if err := interceptor.Enable(chromeCtx); err != nil {
		return nil, err
	}

	// Set up Layer 3 monitor.
	monitor := NewMonitor(enforcer, logger, 10)
	if err := monitor.Enable(chromeCtx); err != nil {
		return nil, err
	}

	// Build crawl state with reduced budget for anonymous pass.
	anonState := NewCrawlState(BrowserScanJob{
		MaxURLs:     min(job.MaxURLs, 100),
		MaxDepth:    min(job.MaxDepth, 2),
		MaxDuration: job.MaxDuration / 4,
	})

	// Seed same URLs as the main crawl.
	for _, seedURL := range job.SeedURLs {
		anonState.Enqueue(seedURL, 0)
	}
	anonState.Enqueue(job.TargetBaseURL, 0)

	// Run anonymous crawl.
	crawler := NewCrawler(enforcer, logger)
	pages, err := crawler.Crawl(ctx, anonState, chromeCtx)
	if err != nil {
		logger.Warn().Err(err).Msg("anonymous crawl encountered error")
	}

	logger.Info().Int("pages", len(pages)).Msg("anonymous crawl completed")

	return SnapshotFromPages(AuthStateAnonymous, pages), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
