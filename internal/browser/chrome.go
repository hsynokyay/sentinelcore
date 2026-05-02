package browser

import (
	"context"
	"fmt"
	"os"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog"
)

// ProfileDir returns the Chrome profile directory path for a given job.
func ProfileDir(jobID string) string {
	return fmt.Sprintf("/tmp/sentinel-chrome-%s", jobID)
}

// ChromeFlags returns the full list of hardened Chrome flags as string pairs
// (flag name, value) for documentation and testing. This does not include
// the user-data-dir flag which is job-specific.
func ChromeFlags(jobID string) []string {
	return []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-software-rasterizer",
		"--disable-dev-shm-usage",
		"--disable-background-networking",
		"--disable-features=ServiceWorker,WebRTC,NetworkPrediction,AutofillServerCommunication",
		"--disable-blink-features=AutomationControlled",
		"--disable-component-update",
		"--disable-default-apps",
		"--dns-prefetch-disable",
		"--no-first-run",
		"--js-flags=--max-old-space-size=512",
		fmt.Sprintf("--user-data-dir=%s", ProfileDir(jobID)),
	}
}

// ChromeAllocatorOpts returns chromedp ExecAllocatorOptions with all
// hardened security flags from the Phase 5a design specification.
func ChromeAllocatorOpts(jobID string) []chromedp.ExecAllocatorOption {
	return []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", "new"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-software-rasterizer", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-features", "ServiceWorker,WebRTC,NetworkPrediction,AutofillServerCommunication"),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("dns-prefetch-disable", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("js-flags", "--max-old-space-size=512"),
		chromedp.Flag("user-data-dir", ProfileDir(jobID)),
	}
}

// ChromeContext creates a hardened Chrome allocator and browser context for
// a scan job. Returns the browser context and a cleanup function that kills
// Chrome and removes the per-job profile directory.
func ChromeContext(parent context.Context, jobID string, logger zerolog.Logger) (context.Context, context.CancelFunc) {
	opts := ChromeAllocatorOpts(jobID)
	allocCtx, allocCancel := chromedp.NewExecAllocator(parent, opts...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(func(format string, args ...interface{}) {
			logger.Debug().Msgf("[chrome] "+format, args...)
		}),
	)

	profileDir := ProfileDir(jobID)
	cleanup := func() {
		browserCancel()
		allocCancel()
		if err := os.RemoveAll(profileDir); err != nil {
			logger.Warn().Err(err).Str("dir", profileDir).Msg("failed to remove Chrome profile dir")
		} else {
			logger.Debug().Str("dir", profileDir).Msg("removed Chrome profile dir")
		}
	}

	return browserCtx, cleanup
}
