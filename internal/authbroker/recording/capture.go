package recording

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

//go:embed capture.js
var captureScript string

// CaptureScript returns the embedded content script that the recorder
// installs on every navigated page via Page.addScriptToEvaluateOnNewDocument.
func CaptureScript() string { return captureScript }

// CapturedEvent is the JSON shape emitted by capture.js through the
// __sentinel_emit CDP runtime binding.
type CapturedEvent struct {
	Kind     string `json:"kind"`
	Selector string `json:"selector,omitempty"`
	T        int64  `json:"t"`
	// Value is included as a defensive field: capture.js never emits a
	// value, so any payload that carries one is rejected.
	Value *string `json:"value,omitempty"`
}

// selectorRE constrains accepted selectors to printable ASCII characters
// commonly seen in CSS selectors. It deliberately rejects newlines, control
// chars, and quotes outside of bracket selectors.
var selectorRE = regexp.MustCompile(`^[A-Za-z0-9_\-#.\[\]="' :>+~()*]+$`)

// ParseAndValidate decodes a payload from the __sentinel_emit binding and
// converts it to a bundles.Action, applying the server-side invariants:
//   - kind must be "click" or "fill"
//   - selector must be ≤256 chars and match the allowed character class
//   - fill events must NOT carry a value
func ParseAndValidate(payload string) (bundles.Action, error) {
	var ev CapturedEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		return bundles.Action{}, fmt.Errorf("recording.capture: bad payload: %w", err)
	}
	if ev.Value != nil {
		return bundles.Action{}, fmt.Errorf("recording.capture: fill events must not carry value")
	}
	if len(ev.Selector) > 256 {
		return bundles.Action{}, fmt.Errorf("recording.capture: selector too long")
	}
	if ev.Selector != "" && !selectorRE.MatchString(ev.Selector) {
		return bundles.Action{}, fmt.Errorf("recording.capture: selector contains invalid characters")
	}

	ts := time.UnixMilli(ev.T).UTC()
	switch ev.Kind {
	case "click":
		return bundles.Action{
			Kind:      bundles.ActionClick,
			Selector:  ev.Selector,
			Timestamp: ts,
		}, nil
	case "fill":
		return bundles.Action{
			Kind:      bundles.ActionFill,
			Selector:  ev.Selector,
			Timestamp: ts,
		}, nil
	default:
		return bundles.Action{}, fmt.Errorf("recording.capture: unknown kind %q", ev.Kind)
	}
}
