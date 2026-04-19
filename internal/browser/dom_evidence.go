package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/sentinelcore/sentinelcore/internal/dast"
)

// DOMSnapshot captures a redacted DOM snapshot as evidence.
type DOMSnapshot struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	BodyText   string `json:"body_text"`   // visible text, truncated
	FormCount  int    `json:"form_count"`
	LinkCount  int    `json:"link_count"`
	ScriptTags int    `json:"script_tags"` // count of inline scripts
	SHA256     string `json:"sha256"`
}

const maxDOMTextSize = 64 * 1024 // 64 KB

// CaptureDOMSnapshot takes a redacted DOM snapshot of the current page.
// Strips script contents and applies sensitive pattern redaction.
func CaptureDOMSnapshot(ctx context.Context, chromeCtx context.Context, pageURL string) (*DOMSnapshot, error) {
	var title string
	var bodyText string
	var formCount, linkCount, scriptCount int

	// Extract page metadata
	if err := chromedp.Run(chromeCtx,
		chromedp.Title(&title),
		chromedp.Evaluate(`document.body ? document.body.innerText.substring(0, 65536) : ''`, &bodyText),
		chromedp.Evaluate(`document.querySelectorAll('form').length`, &formCount),
		chromedp.Evaluate(`document.querySelectorAll('a[href]').length`, &linkCount),
		chromedp.Evaluate(`document.querySelectorAll('script').length`, &scriptCount),
	); err != nil {
		return nil, fmt.Errorf("dom snapshot: %w", err)
	}

	// Truncate body text
	if len(bodyText) > maxDOMTextSize {
		bodyText = bodyText[:maxDOMTextSize]
	}

	// Redact sensitive patterns from body text
	bodyText = RedactBody(bodyText)

	// Hash the snapshot
	hash := sha256.Sum256([]byte(bodyText))

	return &DOMSnapshot{
		URL:        pageURL,
		Title:      title,
		BodyText:   bodyText,
		FormCount:  formCount,
		LinkCount:  linkCount,
		ScriptTags: scriptCount,
		SHA256:     hex.EncodeToString(hash[:]),
	}, nil
}

// PageEvidence bundles all evidence captured for a single page visit.
type PageEvidence struct {
	PageURL       string          `json:"page_url"`
	DOMSnapshot   *DOMSnapshot    `json:"dom_snapshot,omitempty"`
	Screenshot    *dast.Evidence  `json:"screenshot,omitempty"`
	ScreenshotPNG []byte          `json:"-"` // raw PNG bytes, not serialized
	NetworkLog    []NetworkEntry  `json:"network_log,omitempty"`
	CapturedAt    time.Time       `json:"captured_at"`
}

// NetworkEntry records a single network request/response observed during page load.
type NetworkEntry struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	StatusCode int               `json:"status_code"`
	MimeType   string            `json:"mime_type"`
	Headers    map[string]string `json:"headers"` // redacted
	Size       int64             `json:"size"`
	Timing     float64           `json:"timing_ms"`
}

// CapturePageEvidence captures DOM snapshot, screenshot (if enabled), and
// network observations for a page. Screenshot follows the existing privacy model.
func CapturePageEvidence(ctx context.Context, chromeCtx context.Context, pageURL, scanJobID string, captureScreenshot bool) (*PageEvidence, error) {
	ev := &PageEvidence{
		PageURL:    pageURL,
		CapturedAt: time.Now(),
	}

	// DOM snapshot
	snap, err := CaptureDOMSnapshot(ctx, chromeCtx, pageURL)
	if err == nil {
		ev.DOMSnapshot = snap
	}

	// Screenshot (findings-only in practice, but caller controls this)
	if captureScreenshot {
		screenshotEv, pngBytes, err := CaptureScreenshot(chromeCtx, scanJobID, "page-evidence")
		if err == nil {
			ev.Screenshot = screenshotEv
			ev.ScreenshotPNG = pngBytes
		}
		// fail-safe: if screenshot fails, we continue without it
	}

	return ev, nil
}
