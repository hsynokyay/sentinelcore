package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog"
)

// InteractionResult captures the outcome of clicking a safe element.
type InteractionResult struct {
	Target       ClickTarget   `json:"target"`
	TriggeredNav bool          `json:"triggered_nav"` // did the click cause a navigation?
	NewURL       string        `json:"new_url,omitempty"`
	DOMChanged   bool          `json:"dom_changed"` // did visible DOM change?
	Duration     time.Duration `json:"duration"`
	Error        string        `json:"error,omitempty"`
}

// SafeInteractor clicks only safe elements and observes the result.
type SafeInteractor struct {
	logger zerolog.Logger
}

// NewSafeInteractor creates a SafeInteractor.
func NewSafeInteractor(logger zerolog.Logger) *SafeInteractor {
	return &SafeInteractor{logger: logger.With().Str("component", "interactor").Logger()}
}

// DiscoverClickTargets extracts interactive elements from the current page
// and classifies each as safe, unsafe, or unknown.
func (si *SafeInteractor) DiscoverClickTargets(ctx context.Context, chromeCtx context.Context) ([]ClickTarget, error) {
	var raw []struct {
		Tag      string `json:"tag"`
		Text     string `json:"text"`
		Role     string `json:"role"`
		Href     string `json:"href"`
		Type     string `json:"type"`
		Classes  string `json:"classes"`
		Selector string `json:"selector"`
	}

	if err := chromedp.Run(chromeCtx, chromedp.Evaluate(jsExtractClickables, &raw)); err != nil {
		return nil, err
	}

	targets := make([]ClickTarget, 0, len(raw))
	for _, r := range raw {
		ct := ClickTarget{
			Selector: r.Selector,
			Tag:      r.Tag,
			Text:     r.Text,
			Role:     r.Role,
			Href:     r.Href,
			Type:     r.Type,
			Classes:  r.Classes,
		}
		ct.Safety = ClassifyClick(ct)
		targets = append(targets, ct)
	}

	return targets, nil
}

// ClickSafeTargets clicks only ClickSafe elements and observes what happens.
// Returns interaction results. Skips unsafe and unknown elements.
// Budget: stops after maxClicks interactions.
func (si *SafeInteractor) ClickSafeTargets(ctx context.Context, chromeCtx context.Context, targets []ClickTarget, maxClicks int) []InteractionResult {
	var results []InteractionResult
	clicked := 0

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		if clicked >= maxClicks {
			break
		}
		if target.Safety != ClickSafe {
			continue
		}
		if target.Selector == "" {
			continue
		}

		result := si.clickAndObserve(ctx, chromeCtx, target)
		results = append(results, result)
		clicked++
	}

	return results
}

// clickAndObserve clicks a single element and observes navigation/DOM changes.
func (si *SafeInteractor) clickAndObserve(ctx context.Context, chromeCtx context.Context, target ClickTarget) InteractionResult {
	start := time.Now()
	result := InteractionResult{Target: target}

	// Capture URL before click
	var urlBefore string
	if err := chromedp.Run(chromeCtx, chromedp.Location(&urlBefore)); err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result
	}

	// Capture DOM hash before click (simple: body text length as proxy)
	var domBefore int
	chromedp.Run(chromeCtx, chromedp.Evaluate(
		`document.body ? document.body.innerText.length : 0`, &domBefore))

	// Click the element
	if err := chromedp.Run(chromeCtx,
		chromedp.Click(target.Selector, chromedp.ByQuery),
	); err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		si.logger.Debug().Str("selector", target.Selector).Err(err).Msg("click failed")
		return result
	}

	// Brief wait for any navigation or DOM update
	chromedp.Run(chromeCtx, chromedp.Sleep(500*time.Millisecond))

	// Check URL after click
	var urlAfter string
	if err := chromedp.Run(chromeCtx, chromedp.Location(&urlAfter)); err == nil {
		if urlAfter != urlBefore {
			result.TriggeredNav = true
			result.NewURL = urlAfter
		}
	}

	// Check DOM change
	var domAfter int
	chromedp.Run(chromeCtx, chromedp.Evaluate(
		`document.body ? document.body.innerText.length : 0`, &domAfter))
	if domAfter != domBefore {
		result.DOMChanged = true
	}

	result.Duration = time.Since(start)

	si.logger.Debug().
		Str("selector", target.Selector).
		Str("text", target.Text).
		Bool("nav", result.TriggeredNav).
		Bool("dom_changed", result.DOMChanged).
		Msg("safe click completed")

	return result
}
