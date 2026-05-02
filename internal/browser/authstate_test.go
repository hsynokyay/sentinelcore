package browser

import (
	"sort"
	"testing"
)

func TestSnapshotFromPages_Basic(t *testing.T) {
	pages := []PageResult{
		{URL: "https://example.com/", Title: "Home"},
		{URL: "https://example.com/about", Title: "About"},
		{URL: "https://example.com/error", Error: "navigation failed"},
	}
	snap := SnapshotFromPages(AuthStateAnonymous, pages)

	if snap.State != AuthStateAnonymous {
		t.Errorf("expected anonymous, got %s", snap.State)
	}
	if snap.PageCount != 2 {
		t.Errorf("expected 2 pages (error excluded), got %d", snap.PageCount)
	}
	if len(snap.URLs) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(snap.URLs))
	}
}

func TestSnapshotFromPages_Forms(t *testing.T) {
	pages := []PageResult{
		{
			URL: "https://example.com/login",
			Forms: []FormInfo{
				{Action: "/login", Method: "POST", HasCSRF: true},
			},
		},
		{
			URL: "https://example.com/dashboard",
			Forms: []FormInfo{
				{Action: "/settings", Method: "POST", HasCSRF: false},
				{Action: "/profile", Method: "PUT", HasCSRF: true},
			},
		},
	}
	snap := SnapshotFromPages(AuthStateAuthenticated, pages)

	if len(snap.Forms) != 2 {
		t.Errorf("expected 2 form entries, got %d", len(snap.Forms))
	}
	loginNorm := NormalizeURL("https://example.com/login")
	if fs, ok := snap.Forms[loginNorm]; !ok {
		t.Error("missing login form entry")
	} else if fs.Count != 1 {
		t.Errorf("expected 1 form on login, got %d", fs.Count)
	} else if !fs.HasCSRF {
		t.Error("login form should have CSRF")
	}

	dashNorm := NormalizeURL("https://example.com/dashboard")
	if fs, ok := snap.Forms[dashNorm]; !ok {
		t.Error("missing dashboard form entry")
	} else if fs.Count != 2 {
		t.Errorf("expected 2 forms on dashboard, got %d", fs.Count)
	}
}

func TestComputeVariance_AuthOnlyURLs(t *testing.T) {
	anon := &CrawlSnapshot{
		State: AuthStateAnonymous,
		URLs:  map[string]bool{"https://example.com/": true, "https://example.com/login": true},
		Forms: make(map[string]FormSummary),
		PageCount: 2,
	}
	auth := &CrawlSnapshot{
		State: AuthStateAuthenticated,
		URLs: map[string]bool{
			"https://example.com/":          true,
			"https://example.com/login":     true,
			"https://example.com/dashboard": true,
			"https://example.com/settings":  true,
		},
		Forms: make(map[string]FormSummary),
		PageCount: 4,
	}

	v := ComputeVariance(anon, auth)

	sort.Strings(v.AuthOnlyURLs)
	if len(v.AuthOnlyURLs) != 2 {
		t.Fatalf("expected 2 auth-only URLs, got %d: %v", len(v.AuthOnlyURLs), v.AuthOnlyURLs)
	}
	if v.AuthOnlyURLs[0] != "https://example.com/dashboard" {
		t.Errorf("unexpected auth-only URL: %s", v.AuthOnlyURLs[0])
	}

	if len(v.AnonOnlyURLs) != 0 {
		t.Errorf("expected 0 anon-only URLs, got %d", len(v.AnonOnlyURLs))
	}

	if len(v.SharedURLs) != 2 {
		t.Errorf("expected 2 shared URLs, got %d", len(v.SharedURLs))
	}
}

func TestComputeVariance_AnonOnlyURLs(t *testing.T) {
	anon := &CrawlSnapshot{
		State: AuthStateAnonymous,
		URLs:  map[string]bool{"https://example.com/": true, "https://example.com/debug": true},
		Forms: make(map[string]FormSummary),
	}
	auth := &CrawlSnapshot{
		State: AuthStateAuthenticated,
		URLs:  map[string]bool{"https://example.com/": true},
		Forms: make(map[string]FormSummary),
	}

	v := ComputeVariance(anon, auth)

	if len(v.AnonOnlyURLs) != 1 {
		t.Fatalf("expected 1 anon-only URL, got %d", len(v.AnonOnlyURLs))
	}
	if v.AnonOnlyURLs[0] != "https://example.com/debug" {
		t.Errorf("unexpected anon-only URL: %s", v.AnonOnlyURLs[0])
	}
}

func TestComputeVariance_FormDiff(t *testing.T) {
	anon := &CrawlSnapshot{
		State: AuthStateAnonymous,
		URLs:  map[string]bool{"https://example.com/": true},
		Forms: map[string]FormSummary{
			"https://example.com/": {Count: 1, Actions: []string{"/login"}, Methods: []string{"POST"}},
		},
	}
	auth := &CrawlSnapshot{
		State: AuthStateAuthenticated,
		URLs:  map[string]bool{"https://example.com/": true, "https://example.com/admin": true},
		Forms: map[string]FormSummary{
			"https://example.com/":      {Count: 1, Actions: []string{"/login"}, Methods: []string{"POST"}},
			"https://example.com/admin": {Count: 2, Actions: []string{"/delete-user", "/update-role"}, Methods: []string{"POST", "PUT"}},
		},
	}

	v := ComputeVariance(anon, auth)

	if len(v.AuthOnlyForms) != 1 {
		t.Fatalf("expected 1 auth-only form page, got %d", len(v.AuthOnlyForms))
	}
	if _, ok := v.AuthOnlyForms["https://example.com/admin"]; !ok {
		t.Error("expected admin forms in auth-only")
	}
	if len(v.AnonOnlyForms) != 0 {
		t.Errorf("expected 0 anon-only forms, got %d", len(v.AnonOnlyForms))
	}
}

func TestComputeVariance_EmptySnapshots(t *testing.T) {
	anon := &CrawlSnapshot{
		State: AuthStateAnonymous,
		URLs:  make(map[string]bool),
		Forms: make(map[string]FormSummary),
	}
	auth := &CrawlSnapshot{
		State: AuthStateAuthenticated,
		URLs:  make(map[string]bool),
		Forms: make(map[string]FormSummary),
	}

	v := ComputeVariance(anon, auth)
	if len(v.AuthOnlyURLs) != 0 || len(v.AnonOnlyURLs) != 0 || len(v.SharedURLs) != 0 {
		t.Error("empty snapshots should produce empty variance")
	}
}
