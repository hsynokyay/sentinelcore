package browser

import (
	"testing"

	"github.com/rs/zerolog"
)

func testLogger() zerolog.Logger {
	return zerolog.Nop()
}

func TestDOMSnapshot_Fields(t *testing.T) {
	snap := DOMSnapshot{
		URL:        "https://example.com",
		Title:      "Example",
		BodyText:   "Hello World",
		FormCount:  2,
		LinkCount:  10,
		ScriptTags: 3,
		SHA256:     "abc123",
	}
	if snap.FormCount != 2 {
		t.Error("wrong form count")
	}
	if snap.ScriptTags != 3 {
		t.Error("wrong script count")
	}
}

func TestPageEvidence_Fields(t *testing.T) {
	ev := PageEvidence{
		PageURL: "https://example.com/page",
		DOMSnapshot: &DOMSnapshot{
			URL:   "https://example.com/page",
			Title: "Test Page",
		},
	}
	if ev.PageURL != "https://example.com/page" {
		t.Error("wrong page URL")
	}
	if ev.DOMSnapshot == nil {
		t.Error("DOM snapshot should be present")
	}
	if ev.Screenshot != nil {
		t.Error("screenshot should be nil when not captured")
	}
}

func TestNetworkEntry_Fields(t *testing.T) {
	entry := NetworkEntry{
		URL:        "https://example.com/api/data",
		Method:     "GET",
		StatusCode: 200,
		MimeType:   "application/json",
		Size:       1024,
		Timing:     45.2,
	}
	if entry.StatusCode != 200 {
		t.Error("wrong status code")
	}
	if entry.MimeType != "application/json" {
		t.Error("wrong mime type")
	}
}

func TestDOMSnapshot_MaxTextSize(t *testing.T) {
	// Verify the constant is reasonable
	if maxDOMTextSize != 64*1024 {
		t.Errorf("expected maxDOMTextSize=64KB, got %d", maxDOMTextSize)
	}
}
