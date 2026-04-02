package browser

import (
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast"
)

func TestSurfaceFingerprint_Deterministic(t *testing.T) {
	fp1 := SurfaceFingerprint(SurfaceRoute, "https://example.com/page", "GET")
	fp2 := SurfaceFingerprint(SurfaceRoute, "https://example.com/page", "GET")
	if fp1 != fp2 {
		t.Error("same inputs should produce same fingerprint")
	}
	if len(fp1) != 16 {
		t.Errorf("expected 16 hex chars, got %d", len(fp1))
	}
}

func TestSurfaceFingerprint_DifferentInputs(t *testing.T) {
	fp1 := SurfaceFingerprint(SurfaceRoute, "https://example.com/a", "GET")
	fp2 := SurfaceFingerprint(SurfaceRoute, "https://example.com/b", "GET")
	fp3 := SurfaceFingerprint(SurfaceForm, "https://example.com/a", "POST")
	if fp1 == fp2 {
		t.Error("different URLs should produce different fingerprints")
	}
	if fp1 == fp3 {
		t.Error("different types should produce different fingerprints")
	}
}

func TestNewSurfaceInventory(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	if inv.ProjectID != "proj-1" {
		t.Error("wrong project ID")
	}
	if len(inv.Entries) != 0 {
		t.Error("new inventory should be empty")
	}
}

func TestInventory_AddEntry_Dedup(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()

	entry := &SurfaceEntry{
		ID:          "fp1",
		Type:        SurfaceRoute,
		URL:         "https://example.com/",
		Method:      "GET",
		Exposure:    ExposurePublic,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	inv.AddEntry(entry)
	inv.AddEntry(entry) // duplicate

	if len(inv.Entries) != 1 {
		t.Errorf("expected 1 entry after dedup, got %d", len(inv.Entries))
	}
	if inv.Entries["fp1"].ScanCount != 2 {
		t.Errorf("expected scan count 2, got %d", inv.Entries["fp1"].ScanCount)
	}
}

func TestInventory_QueryByType(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()

	inv.AddEntry(&SurfaceEntry{ID: "r1", Type: SurfaceRoute, URL: "https://a.com/", FirstSeenAt: now, LastSeenAt: now})
	inv.AddEntry(&SurfaceEntry{ID: "r2", Type: SurfaceRoute, URL: "https://b.com/", FirstSeenAt: now, LastSeenAt: now})
	inv.AddEntry(&SurfaceEntry{ID: "f1", Type: SurfaceForm, URL: "https://a.com/form", FirstSeenAt: now, LastSeenAt: now})

	routes := inv.QueryByType(SurfaceRoute)
	if len(routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(routes))
	}

	forms := inv.QueryByType(SurfaceForm)
	if len(forms) != 1 {
		t.Errorf("expected 1 form, got %d", len(forms))
	}
}

func TestInventory_QueryByExposure(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()

	inv.AddEntry(&SurfaceEntry{ID: "p1", Type: SurfaceRoute, URL: "https://a.com/", Exposure: ExposurePublic, FirstSeenAt: now, LastSeenAt: now})
	inv.AddEntry(&SurfaceEntry{ID: "a1", Type: SurfaceRoute, URL: "https://a.com/admin", Exposure: ExposureAuthenticated, FirstSeenAt: now, LastSeenAt: now})
	inv.AddEntry(&SurfaceEntry{ID: "b1", Type: SurfaceRoute, URL: "https://a.com/shared", Exposure: ExposureBoth, FirstSeenAt: now, LastSeenAt: now})

	public := inv.QueryByExposure(ExposurePublic)
	if len(public) != 1 {
		t.Errorf("expected 1 public, got %d", len(public))
	}
	auth := inv.QueryByExposure(ExposureAuthenticated)
	if len(auth) != 1 {
		t.Errorf("expected 1 authenticated, got %d", len(auth))
	}
}

func TestInventory_QueryWithFindings(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()

	inv.AddEntry(&SurfaceEntry{ID: "f1", Type: SurfaceRoute, URL: "https://a.com/vuln", FindingIDs: []string{"finding-1"}, FirstSeenAt: now, LastSeenAt: now})
	inv.AddEntry(&SurfaceEntry{ID: "f2", Type: SurfaceRoute, URL: "https://a.com/safe", FirstSeenAt: now, LastSeenAt: now})

	withFindings := inv.QueryWithFindings()
	if len(withFindings) != 1 {
		t.Errorf("expected 1 entry with findings, got %d", len(withFindings))
	}
}

func TestInventory_ComputeStats(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()

	inv.AddEntry(&SurfaceEntry{ID: "r1", Type: SurfaceRoute, URL: "https://a.com/", Exposure: ExposurePublic, Metadata: EntryMetadata{FieldCount: 2}, FirstSeenAt: now, LastSeenAt: now})
	inv.AddEntry(&SurfaceEntry{ID: "r2", Type: SurfaceRoute, URL: "https://a.com/admin", Exposure: ExposureAuthenticated, FirstSeenAt: now, LastSeenAt: now})
	inv.AddEntry(&SurfaceEntry{ID: "c1", Type: SurfaceClickable, URL: "https://a.com/", Metadata: EntryMetadata{Safety: "unsafe"}, FirstSeenAt: now, LastSeenAt: now})
	inv.AddEntry(&SurfaceEntry{ID: "f1", Type: SurfaceForm, URL: "https://a.com/form", FindingIDs: []string{"x"}, FirstSeenAt: now, LastSeenAt: now})

	inv.ComputeStats()

	if inv.Stats.TotalEntries != 4 {
		t.Errorf("expected 4 total, got %d", inv.Stats.TotalEntries)
	}
	if inv.Stats.ByType["route"] != 2 {
		t.Errorf("expected 2 routes, got %d", inv.Stats.ByType["route"])
	}
	if inv.Stats.RoutesWithForms != 1 {
		t.Errorf("expected 1 route with forms, got %d", inv.Stats.RoutesWithForms)
	}
	if inv.Stats.UnsafeClickables != 1 {
		t.Errorf("expected 1 unsafe clickable, got %d", inv.Stats.UnsafeClickables)
	}
	if inv.Stats.EntriesWithFindings != 1 {
		t.Errorf("expected 1 entry with findings, got %d", inv.Stats.EntriesWithFindings)
	}
}

func TestBuildInventory_FromPages(t *testing.T) {
	pages := []PageResult{
		{
			URL:   "https://example.com/",
			Title: "Home",
			Depth: 0,
			Forms: []FormInfo{
				{Action: "/login", Method: "POST", HasCSRF: true, Fields: []FormField{{Name: "email", Type: "text"}}},
			},
			ClickTargets: []ClickTarget{
				{Tag: "button", Text: "Delete", Safety: ClickUnsafe, Selector: "#del"},
				{Tag: "a", Text: "About", Safety: ClickSafe, Href: "/about", Selector: "#about"},
			},
		},
		{
			URL:   "https://example.com/about",
			Title: "About",
			Depth: 1,
		},
		{
			URL:   "https://example.com/broken",
			Error: "timeout",
		},
	}

	findings := []dast.Finding{
		{
			ID:  "f1",
			URL: "https://example.com/",
			Evidence: &dast.Evidence{SHA256: "abc123"},
		},
	}

	inv := BuildInventory("proj-1", "scan-1", pages, nil, findings)

	if inv.Stats.TotalEntries == 0 {
		t.Fatal("expected entries")
	}

	// Should have routes for / and /about (not /broken)
	routes := inv.QueryByType(SurfaceRoute)
	if len(routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(routes))
	}

	// Should have 1 form
	forms := inv.QueryByType(SurfaceForm)
	if len(forms) != 1 {
		t.Errorf("expected 1 form, got %d", len(forms))
	}

	// Should have 1 clickable (unsafe only — safe is filtered)
	clicks := inv.QueryByType(SurfaceClickable)
	if len(clicks) != 1 {
		t.Errorf("expected 1 unsafe clickable, got %d", len(clicks))
	}

	// Home route should have finding association
	homeEntries := inv.QueryWithFindings()
	if len(homeEntries) == 0 {
		t.Error("expected at least 1 entry with findings")
	}
}

func TestBuildInventory_WithVariance(t *testing.T) {
	pages := []PageResult{
		{URL: "https://example.com/", Title: "Home", Depth: 0},
		{URL: "https://example.com/admin", Title: "Admin", Depth: 1},
	}
	variance := &AuthStateVariance{
		AuthOnlyURLs: []string{"https://example.com/admin"},
		SharedURLs:   []string{"https://example.com/"},
	}

	inv := BuildInventory("proj-1", "scan-1", pages, variance, nil)

	// Home should be ExposureBoth, admin should be ExposureAuthenticated
	for _, e := range inv.Entries {
		if e.URL == "https://example.com/" && e.Exposure != ExposureBoth {
			t.Errorf("home should be ExposureBoth, got %s", e.Exposure)
		}
		if e.URL == "https://example.com/admin" && e.Exposure != ExposureAuthenticated {
			t.Errorf("admin should be ExposureAuthenticated, got %s", e.Exposure)
		}
	}
}

func TestBuildInventory_Empty(t *testing.T) {
	inv := BuildInventory("proj-1", "scan-1", nil, nil, nil)
	if inv.Stats.TotalEntries != 0 {
		t.Errorf("expected 0 entries, got %d", inv.Stats.TotalEntries)
	}
}

func TestAppendUnique(t *testing.T) {
	s := []string{"a", "b"}
	s = appendUnique(s, "b") // duplicate
	if len(s) != 2 {
		t.Errorf("expected 2, got %d", len(s))
	}
	s = appendUnique(s, "c")
	if len(s) != 3 {
		t.Errorf("expected 3, got %d", len(s))
	}
}
