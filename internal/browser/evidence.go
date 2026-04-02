package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/dast"
)

// RedactCDPHeaders applies SensitiveHeaders redaction to CDP header maps.
// CDP headers are map[string]interface{}; this returns a clean map[string]string
// with sensitive values replaced by [REDACTED].
func RedactCDPHeaders(headers map[string]interface{}) map[string]string {
	result := make(map[string]string, len(headers))
	for k, v := range headers {
		strVal, ok := v.(string)
		if !ok {
			strVal = fmt.Sprintf("%v", v)
		}
		if dast.SensitiveHeaders[strings.ToLower(k)] {
			result[k] = "[REDACTED]"
		} else {
			result[k] = strVal
		}
	}
	return result
}

// RedactBody applies SensitivePatterns regex replacements to a response body
// string, replacing credential-like values with [REDACTED].
func RedactBody(body string) string {
	for _, re := range dast.SensitivePatterns {
		body = re.ReplaceAllString(body, "[REDACTED]")
	}
	return body
}

// CaptureScreenshot takes a privacy-safe screenshot of the current page.
// 1. Injects CSS blur on all input/textarea elements.
// 2. Replaces password field values with [REDACTED].
// 3. Takes screenshot and hashes with SHA-256.
// If blur injection fails, returns an error (fail-safe: no unredacted screenshots).
func CaptureScreenshot(ctx context.Context, scanJobID, ruleID string) (*dast.Evidence, []byte, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("browser/evidence: context is nil")
	}

	// Inject CSS blur on all inputs.
	blurJS := `(function(){var s=document.createElement('style');s.textContent='input,textarea{filter:blur(5px)!important}';document.head.appendChild(s);return true})()`
	var blurOK bool
	if err := chromedp.Evaluate(blurJS, &blurOK).Do(ctx); err != nil {
		return nil, nil, fmt.Errorf("browser/evidence: blur injection failed (fail-safe: no unredacted screenshots): %w", err)
	}

	// Replace password field values.
	redactJS := `(function(){var p=document.querySelectorAll('input[type="password"]');p.forEach(function(e){e.value='[REDACTED]'});return p.length})()`
	var redactCount int
	_ = chromedp.Evaluate(redactJS, &redactCount).Do(ctx)

	// Take screenshot.
	var pngBytes []byte
	if err := chromedp.FullScreenshot(&pngBytes, 90).Do(ctx); err != nil {
		return nil, nil, fmt.Errorf("browser/evidence: screenshot failed: %w", err)
	}

	// Hash with SHA-256.
	hash := sha256.Sum256(pngBytes)

	evidence := &dast.Evidence{
		ID:         uuid.New().String(),
		ScanJobID:  scanJobID,
		RuleID:     ruleID,
		SHA256:     hex.EncodeToString(hash[:]),
		CapturedAt: time.Now(),
		Metadata: map[string]string{
			"type":            "screenshot",
			"blur_applied":    "true",
			"fields_redacted": fmt.Sprintf("%d", redactCount),
		},
	}

	return evidence, pngBytes, nil
}
