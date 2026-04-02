package browser

import (
	"strings"
	"testing"
)

func TestChromeFlags(t *testing.T) {
	flags := ChromeFlags("test-job-123")

	requiredFlags := []string{
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-software-rasterizer",
		"--disable-dev-shm-usage",
		"--disable-background-networking",
		"--disable-features=",
		"--disable-blink-features=AutomationControlled",
		"--disable-component-update",
		"--disable-default-apps",
		"--dns-prefetch-disable",
		"--no-first-run",
		"--js-flags=--max-old-space-size=512",
		"--user-data-dir=",
	}

	for _, req := range requiredFlags {
		found := false
		for _, f := range flags {
			if strings.Contains(f, req) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required flag %q not found in ChromeFlags output", req)
		}
	}

	// Verify security-critical features are disabled.
	disabledFeatures := []string{"ServiceWorker", "WebRTC", "NetworkPrediction", "AutofillServerCommunication"}
	for _, feat := range disabledFeatures {
		found := false
		for _, f := range flags {
			if strings.Contains(f, feat) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("disabled feature %q not found in ChromeFlags", feat)
		}
	}
}

func TestChromeAllocatorOpts(t *testing.T) {
	opts := ChromeAllocatorOpts("test-job-456")
	// We set 14 flags.
	if len(opts) < 14 {
		t.Errorf("expected at least 14 allocator options, got %d", len(opts))
	}
}

func TestProfileDir(t *testing.T) {
	d1 := ProfileDir("job-aaa")
	d2 := ProfileDir("job-bbb")

	if d1 == d2 {
		t.Error("different job IDs should produce different profile directories")
	}
	if d1 != "/tmp/sentinel-chrome-job-aaa" {
		t.Errorf("unexpected profile dir: %s", d1)
	}
}
