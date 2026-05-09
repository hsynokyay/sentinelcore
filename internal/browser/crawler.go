package browser

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// jsExtractLinks is the JavaScript snippet used to extract all absolute href values from the page.
const jsExtractLinks = `Array.from(document.querySelectorAll('a[href]')).map(a => a.href).filter(h => h.startsWith('http'))`

// jsExtractForms is the JavaScript snippet used to extract form metadata from the page.
const jsExtractForms = `(function() {
	var results = [];
	document.querySelectorAll('form').forEach(function(form) {
		var fields = [];
		var hasCSRF = false;
		var buttonTexts = [];
		form.querySelectorAll('input, select, textarea').forEach(function(el) {
			var name = el.getAttribute('name') || '';
			var type = el.getAttribute('type') || el.tagName.toLowerCase();
			var value = '';
			if (type === 'hidden') {
				value = el.value || '';
			}
			fields.push({name: name, type: type, value: value});
			if (name && (name.toLowerCase().indexOf('csrf') !== -1 || name.toLowerCase().indexOf('_token') !== -1)) {
				hasCSRF = true;
			}
		});
		form.querySelectorAll('button, input[type="submit"]').forEach(function(btn) {
			buttonTexts.push(btn.textContent || btn.value || '');
		});
		results.push({
			action: form.getAttribute('action') || '',
			method: (form.getAttribute('method') || 'GET').toUpperCase(),
			fields: fields,
			hasCSRF: hasCSRF,
			buttonTexts: buttonTexts
		});
	});
	return results;
})()`

// MaxSafeClicksPerPage limits how many safe elements are clicked per page.
const MaxSafeClicksPerPage = 10

// Crawler performs shallow, non-destructive browser crawling.
type Crawler struct {
	enforcer   *scope.Enforcer
	interactor *SafeInteractor
	logger     zerolog.Logger
}

// NewCrawler creates a new Crawler with scope enforcement and logging.
func NewCrawler(enforcer *scope.Enforcer, logger zerolog.Logger) *Crawler {
	return &Crawler{
		enforcer:   enforcer,
		interactor: NewSafeInteractor(logger),
		logger:     logger.With().Str("component", "crawler").Logger(),
	}
}

// rawFormResult mirrors the JSON structure returned by jsExtractForms.
type rawFormResult struct {
	Action      string     `json:"action"`
	Method      string     `json:"method"`
	Fields      []rawField `json:"fields"`
	HasCSRF     bool       `json:"hasCSRF"`
	ButtonTexts []string   `json:"buttonTexts"`
}

// rawField mirrors a single field from the form extraction JS.
type rawField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Crawl performs BFS traversal starting from seed URLs already present in state.Queue.
// Returns PageResults for each visited page. Respects all budget limits.
func (c *Crawler) Crawl(ctx context.Context, state *CrawlState, chromeCtx context.Context) ([]PageResult, error) {
	var pages []PageResult

	for state.CanContinue() {
		// Check for context cancellation.
		if ctx.Err() != nil {
			return pages, ctx.Err()
		}

		entry, ok := state.Dequeue()
		if !ok {
			break
		}

		// Validate scope before navigating.
		if err := c.enforcer.CheckRequest(ctx, entry.URL); err != nil {
			c.logger.Debug().Str("url", entry.URL).Msg("skipping out-of-scope URL")
			continue
		}

		page := c.visitPage(ctx, chromeCtx, entry)
		pages = append(pages, page)

		// Enqueue discovered links.
		for _, link := range page.Links {
			if c.enforcer.CheckRequest(ctx, link) == nil {
				state.Enqueue(link, entry.Depth+1)
			}
		}
	}

	return pages, nil
}

// visitPage navigates to a single URL and extracts page data.
func (c *Crawler) visitPage(ctx context.Context, chromeCtx context.Context, entry CrawlEntry) PageResult {
	start := time.Now()
	page := PageResult{
		URL:   entry.URL,
		Depth: entry.Depth,
	}

	// Navigate and wait for body.
	if err := chromedp.Run(chromeCtx,
		chromedp.Navigate(entry.URL),
		chromedp.WaitReady("body"),
	); err != nil {
		page.Error = fmt.Sprintf("navigation failed: %v", err)
		page.LoadTime = time.Since(start)
		c.logger.Warn().Str("url", entry.URL).Err(err).Msg("page navigation failed")
		return page
	}

	page.LoadTime = time.Since(start)

	// Extract title.
	_ = chromedp.Run(chromeCtx, chromedp.Title(&page.Title))

	// Extract links.
	var links []string
	if err := chromedp.Run(chromeCtx, chromedp.Evaluate(jsExtractLinks, &links)); err != nil {
		c.logger.Warn().Str("url", entry.URL).Err(err).Msg("link extraction failed")
	}

	// Resolve relative links and deduplicate.
	seen := make(map[string]bool)
	for _, href := range links {
		resolved := ResolveURL(href, entry.URL)
		if resolved == "" {
			continue
		}
		normalized := NormalizeURL(resolved)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		page.Links = append(page.Links, resolved)
	}

	// Extract forms.
	var rawForms []rawFormResult
	if err := chromedp.Run(chromeCtx, chromedp.Evaluate(jsExtractForms, &rawForms)); err != nil {
		c.logger.Warn().Str("url", entry.URL).Err(err).Msg("form extraction failed")
	}

	for _, rf := range rawForms {
		fi := FormInfo{
			Action:  rf.Action,
			Method:  rf.Method,
			HasCSRF: rf.HasCSRF,
		}
		for _, f := range rf.Fields {
			fi.Fields = append(fi.Fields, FormField{
				Name:  f.Name,
				Type:  f.Type,
				Value: f.Value,
			})
		}

		// Determine if the form action is safe (non-destructive).
		destructive := IsDestructiveAction(rf.Action)
		if !destructive {
			for _, btnText := range rf.ButtonTexts {
				if IsDestructiveAction(btnText) {
					destructive = true
					break
				}
			}
		}
		fi.IsSafe = !destructive

		page.Forms = append(page.Forms, fi)
	}

	// Discover clickable elements and classify safety.
	targets, err := c.interactor.DiscoverClickTargets(ctx, chromeCtx)
	if err != nil {
		c.logger.Debug().Err(err).Str("url", entry.URL).Msg("click target discovery failed")
	} else {
		page.ClickTargets = targets

		// Click safe elements to discover SPA routes and hidden content.
		interactions := c.interactor.ClickSafeTargets(ctx, chromeCtx, targets, MaxSafeClicksPerPage)
		page.Interactions = interactions

		// If any safe clicks triggered navigation to a new in-scope URL, enqueue it.
		for _, ir := range interactions {
			if ir.TriggeredNav && ir.NewURL != "" {
				if c.enforcer.CheckRequest(ctx, ir.NewURL) == nil {
					// The new URL will be enqueued by the Crawl() caller
					page.Links = append(page.Links, ir.NewURL)
				}
			}
		}
	}

	c.logger.Debug().
		Str("url", entry.URL).
		Int("depth", entry.Depth).
		Int("links", len(page.Links)).
		Int("forms", len(page.Forms)).
		Int("click_targets", len(page.ClickTargets)).
		Int("interactions", len(page.Interactions)).
		Str("title", page.Title).
		Msg("page visited")

	return page
}

// IsCSRFField checks if a form field name indicates a CSRF token.
func IsCSRFField(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "csrf") || strings.Contains(lower, "_token")
}
