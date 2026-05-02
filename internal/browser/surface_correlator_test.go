package browser

import (
	"testing"
	"time"

	corr "github.com/sentinelcore/sentinelcore/pkg/correlation"
)

func TestEnrichInventory_ExactURLMatch(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()
	inv.AddEntry(&SurfaceEntry{
		ID: "r1", Type: SurfaceRoute, URL: "https://example.com/login",
		Method: "GET", FirstSeenAt: now, LastSeenAt: now,
	})

	findings := []*corr.RawFinding{
		{ID: "f1", URL: "https://example.com/login", CWEID: 352, Type: "dast"},
	}

	result := EnrichInventory(inv, findings)

	if result.Stats.TotalCorrelations == 0 {
		t.Fatal("expected at least 1 correlation")
	}
	found := false
	for _, c := range result.Correlations {
		if c.MatchType == MatchExactURL && c.SurfaceID == "r1" && c.FindingID == "f1" {
			found = true
			if c.Score != 1.0 {
				t.Errorf("exact URL match should have score 1.0, got %f", c.Score)
			}
			if c.Confidence != "high" {
				t.Errorf("exact URL match should be high confidence, got %s", c.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected exact URL match correlation")
	}

	// Entry should now have the finding ID
	entry := inv.Entries["r1"]
	if len(entry.FindingIDs) == 0 {
		t.Error("entry should have finding ID after enrichment")
	}
}

func TestEnrichInventory_PathPrefixMatch(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()
	inv.AddEntry(&SurfaceEntry{
		ID: "r1", Type: SurfaceRoute, URL: "https://example.com/api/users",
		Method: "GET", FirstSeenAt: now, LastSeenAt: now,
	})

	findings := []*corr.RawFinding{
		{ID: "f1", URL: "https://example.com/api/users/profile", Type: "dast"},
	}

	result := EnrichInventory(inv, findings)

	found := false
	for _, c := range result.Correlations {
		if c.MatchType == MatchPathPrefix {
			found = true
			if c.Score < 0.5 {
				t.Errorf("path prefix overlap should be >= 0.5, got %f", c.Score)
			}
		}
	}
	if !found {
		t.Error("expected path prefix match")
	}
}

func TestEnrichInventory_FormActionMatch(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()
	inv.AddEntry(&SurfaceEntry{
		ID: "f1", Type: SurfaceForm, URL: "https://example.com/page",
		Method: "POST", FirstSeenAt: now, LastSeenAt: now,
		Metadata: EntryMetadata{FormAction: "https://example.com/api/submit"},
	})

	findings := []*corr.RawFinding{
		{ID: "finding-1", URL: "https://example.com/api/submit", Type: "dast"},
	}

	result := EnrichInventory(inv, findings)

	found := false
	for _, c := range result.Correlations {
		if c.MatchType == MatchFormAction {
			found = true
			if c.Score != 0.9 {
				t.Errorf("form action match should have score 0.9, got %f", c.Score)
			}
		}
	}
	if !found {
		t.Error("expected form action match")
	}
}

func TestEnrichInventory_ParameterNameMatch(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()
	inv.AddEntry(&SurfaceEntry{
		ID: "f1", Type: SurfaceForm, URL: "https://example.com/login",
		Method: "POST", FirstSeenAt: now, LastSeenAt: now,
		Metadata: EntryMetadata{
			Fields: []FormField{
				{Name: "username", Type: "text"},
				{Name: "password", Type: "password"},
			},
		},
	})

	findings := []*corr.RawFinding{
		{ID: "finding-1", URL: "https://example.com/other", Parameter: "username", Type: "dast"},
	}

	result := EnrichInventory(inv, findings)

	found := false
	for _, c := range result.Correlations {
		if c.MatchType == MatchParameterName {
			found = true
			if c.Score != 0.8 {
				t.Errorf("parameter match should have score 0.8, got %f", c.Score)
			}
			if c.Confidence != "medium" {
				t.Errorf("parameter match should be medium confidence, got %s", c.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected parameter name match")
	}
}

func TestEnrichInventory_NoMatches(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()
	inv.AddEntry(&SurfaceEntry{
		ID: "r1", Type: SurfaceRoute, URL: "https://example.com/about",
		Method: "GET", FirstSeenAt: now, LastSeenAt: now,
	})

	findings := []*corr.RawFinding{
		{ID: "f1", URL: "https://other.com/page", Type: "dast"},
	}

	result := EnrichInventory(inv, findings)

	if result.Stats.TotalCorrelations != 0 {
		t.Errorf("expected 0 correlations, got %d", result.Stats.TotalCorrelations)
	}
	if result.Stats.EnrichedEntries != 0 {
		t.Errorf("expected 0 enriched entries, got %d", result.Stats.EnrichedEntries)
	}
}

func TestEnrichInventory_EmptyInputs(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	result := EnrichInventory(inv, nil)
	if result.Stats.TotalCorrelations != 0 {
		t.Error("empty inputs should produce 0 correlations")
	}
}

func TestEnrichInventory_Stats(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	now := time.Now()
	inv.AddEntry(&SurfaceEntry{
		ID: "r1", Type: SurfaceRoute, URL: "https://example.com/a",
		Method: "GET", FirstSeenAt: now, LastSeenAt: now,
	})
	inv.AddEntry(&SurfaceEntry{
		ID: "r2", Type: SurfaceRoute, URL: "https://example.com/b",
		Method: "GET", FirstSeenAt: now, LastSeenAt: now,
	})

	findings := []*corr.RawFinding{
		{ID: "f1", URL: "https://example.com/a", Type: "dast"},
	}

	result := EnrichInventory(inv, findings)

	if result.Stats.EnrichedEntries != 1 {
		t.Errorf("expected 1 enriched entry, got %d", result.Stats.EnrichedEntries)
	}
	if result.Stats.ByMatchType["exact_url"] != 1 {
		t.Errorf("expected 1 exact_url match, got %d", result.Stats.ByMatchType["exact_url"])
	}
}

func TestPathOverlap(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want float64
	}{
		{"identical", "/api/users", "/api/users", 1.0},
		{"prefix", "/api/users", "/api/users/profile", 2.0 / 3.0},
		{"partial", "/api/users", "/api/teams", 0.5},
		{"no overlap", "/foo", "/bar", 0.0},
		{"empty", "", "/api", 0.0},
		{"root", "/", "/api", 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathOverlap(tt.a, tt.b)
			diff := got - tt.want
			if diff < -0.01 || diff > 0.01 {
				t.Errorf("pathOverlap(%q, %q) = %f, want %f", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"/api/users/profile", 3},
		{"/", 0},
		{"", 0},
		{"/a", 1},
	}
	for _, tt := range tests {
		segs := splitPath(tt.input)
		if len(segs) != tt.want {
			t.Errorf("splitPath(%q) = %d segments, want %d", tt.input, len(segs), tt.want)
		}
	}
}

func TestScoreToConfidence(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{1.0, "high"},
		{0.8, "high"},
		{0.7, "medium"},
		{0.5, "medium"},
		{0.4, "low"},
		{0.3, "low"},
		{0.2, ""},
		{0.0, ""},
	}
	for _, tt := range tests {
		got := scoreToConfidence(tt.score)
		if got != tt.want {
			t.Errorf("scoreToConfidence(%f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestCorrelationFingerprint_Deterministic(t *testing.T) {
	fp1 := CorrelationFingerprint("s1", "f1", MatchExactURL)
	fp2 := CorrelationFingerprint("s1", "f1", MatchExactURL)
	if fp1 != fp2 {
		t.Error("same inputs should produce same fingerprint")
	}

	fp3 := CorrelationFingerprint("s1", "f1", MatchPathPrefix)
	if fp1 == fp3 {
		t.Error("different match types should produce different fingerprints")
	}
}
