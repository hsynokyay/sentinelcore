package browser

import (
	"testing"
)

func TestAnalyzePages_CSRFDetection(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/login",
			Forms: []FormInfo{
				{Action: "/login", Method: "POST", HasCSRF: false, IsSafe: true},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")

	if len(result.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(result.Observations))
	}
	if result.Observations[0].Type != ObsMissingCSRF {
		t.Errorf("expected missing CSRF, got %s", result.Observations[0].Type)
	}
	if result.Observations[0].CWEID != 352 {
		t.Errorf("expected CWE-352, got %d", result.Observations[0].CWEID)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Category != "csrf" {
		t.Errorf("expected category csrf, got %s", result.Findings[0].Category)
	}
}

func TestAnalyzePages_CSRFSkipsGET(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/search",
			Forms: []FormInfo{
				{Action: "/search", Method: "GET", HasCSRF: false},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")
	if len(result.Observations) != 0 {
		t.Errorf("GET forms should not trigger CSRF finding, got %d observations", len(result.Observations))
	}
}

func TestAnalyzePages_CSRFSkipsProtected(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/form",
			Forms: []FormInfo{
				{Action: "/form", Method: "POST", HasCSRF: true},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")
	if len(result.Observations) != 0 {
		t.Errorf("forms with CSRF should not trigger finding, got %d", len(result.Observations))
	}
}

func TestAnalyzePages_FormHTTP(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/page",
			Forms: []FormInfo{
				{Action: "http://example.com/submit", Method: "POST"},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")

	found := false
	for _, obs := range result.Observations {
		if obs.Type == ObsFormToHTTP {
			found = true
			if obs.Severity != "high" {
				t.Errorf("expected high severity, got %s", obs.Severity)
			}
		}
	}
	if !found {
		t.Error("expected form-to-HTTP observation")
	}
}

func TestAnalyzePages_FormHTTP_SkipsHTTPPage(t *testing.T) {
	pages := []PageResult{
		{
			URL: "http://example.com/page",
			Forms: []FormInfo{
				{Action: "http://example.com/submit", Method: "POST"},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")
	for _, obs := range result.Observations {
		if obs.Type == ObsFormToHTTP {
			t.Error("should not flag HTTP form on HTTP page")
		}
	}
}

func TestAnalyzePages_MixedContent(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/page",
			Evidence: &PageEvidence{
				NetworkLog: []NetworkEntry{
					{URL: "https://example.com/style.css", StatusCode: 200},
					{URL: "http://cdn.example.com/script.js", StatusCode: 200},
				},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")

	found := false
	for _, obs := range result.Observations {
		if obs.Type == ObsMixedContent {
			found = true
		}
	}
	if !found {
		t.Error("expected mixed content observation")
	}
}

func TestAnalyzePages_InlineScripts(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/page",
			Evidence: &PageEvidence{
				DOMSnapshot: &DOMSnapshot{ScriptTags: 15},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")

	found := false
	for _, obs := range result.Observations {
		if obs.Type == ObsInlineScript {
			found = true
			if obs.Confidence != "low" {
				t.Errorf("expected low confidence, got %s", obs.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected inline script observation")
	}
}

func TestAnalyzePages_InlineScripts_SkipsFew(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/page",
			Evidence: &PageEvidence{
				DOMSnapshot: &DOMSnapshot{ScriptTags: 5},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")
	for _, obs := range result.Observations {
		if obs.Type == ObsInlineScript {
			t.Error("should not flag pages with < 10 inline scripts")
		}
	}
}

func TestAnalyzePages_AutoComplete(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/login",
			Forms: []FormInfo{
				{
					Action: "/login",
					Method: "POST",
					HasCSRF: true, // don't also trigger CSRF
					Fields: []FormField{
						{Name: "username", Type: "text"},
						{Name: "password", Type: "password"},
					},
				},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")

	found := false
	for _, obs := range result.Observations {
		if obs.Type == ObsAutoComplete {
			found = true
		}
	}
	if !found {
		t.Error("expected autocomplete observation for password field")
	}
}

func TestAnalyzePages_SkipsErrorPages(t *testing.T) {
	pages := []PageResult{
		{
			URL:   "https://example.com/broken",
			Error: "navigation failed",
			Forms: []FormInfo{
				{Action: "/form", Method: "POST", HasCSRF: false},
			},
		},
	}
	result := AnalyzePages(pages, "scan-1", "proj-1")
	if len(result.Observations) != 0 {
		t.Error("should skip error pages")
	}
}

func TestAnalyzePages_FindingsHaveDeterministicFingerprints(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/form",
			Forms: []FormInfo{
				{Action: "/submit", Method: "POST", HasCSRF: false},
			},
		},
	}

	r1 := AnalyzePages(pages, "scan-1", "proj-1")
	r2 := AnalyzePages(pages, "scan-1", "proj-1")

	if len(r1.Findings) == 0 || len(r2.Findings) == 0 {
		t.Fatal("expected findings")
	}
	// Fingerprints should be the same for same input
	if r1.Findings[0].Evidence.SHA256 != r2.Findings[0].Evidence.SHA256 {
		t.Error("fingerprints should be deterministic")
	}
}

func TestComputeFingerprint_Deterministic(t *testing.T) {
	fp1 := computeFingerprint("a", "b", "c")
	fp2 := computeFingerprint("a", "b", "c")
	if fp1 != fp2 {
		t.Error("same inputs should produce same fingerprint")
	}

	fp3 := computeFingerprint("a", "b", "d")
	if fp1 == fp3 {
		t.Error("different inputs should produce different fingerprints")
	}
}

func TestComputeFingerprint_NotEmpty(t *testing.T) {
	fp := computeFingerprint("test")
	if fp == "" {
		t.Error("fingerprint should not be empty")
	}
	if len(fp) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("expected 64 char hex, got %d", len(fp))
	}
}
