package browser

import "testing"

func TestVarianceRules_UniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, rule := range VarianceRules {
		if seen[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		seen[rule.ID] = true
	}
}

func TestVarianceRules_ValidSeverity(t *testing.T) {
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, rule := range VarianceRules {
		if !valid[rule.Severity] {
			t.Errorf("rule %s has invalid severity: %s", rule.ID, rule.Severity)
		}
	}
}

func TestVarianceRuleByType(t *testing.T) {
	rule := VarianceRuleByType(VarAnonOnlyRoute)
	if rule == nil {
		t.Fatal("expected rule for anon-only route")
	}
	if rule.ID != "VARIANCE-002" {
		t.Errorf("wrong rule ID: %s", rule.ID)
	}
	if rule.CWEID != 284 {
		t.Errorf("expected CWE-284, got %d", rule.CWEID)
	}

	unknown := VarianceRuleByType(VarianceObservationType("nonexistent"))
	if unknown != nil {
		t.Error("expected nil for unknown type")
	}
}

func TestAnalyzeVariance_AnonOnlyRoutes_GenerateFindings(t *testing.T) {
	variance := &AuthStateVariance{
		AnonOnlyURLs:  []string{"https://example.com/debug", "https://example.com/admin-reset"},
		AuthOnlyURLs:  []string{"https://example.com/dashboard"},
		SharedURLs:    []string{"https://example.com/"},
		AnonOnlyForms: make(map[string]FormSummary),
		AuthOnlyForms: make(map[string]FormSummary),
		AnonPageCount: 4,
		AuthPageCount: 2,
	}

	result := AnalyzeVariance(variance, "scan-1")

	// Should generate findings for anon-only routes (suspicious)
	findingCount := 0
	for _, f := range result.Findings {
		if f.Category == "access_control" && f.Severity == "medium" {
			findingCount++
		}
	}
	if findingCount != 2 {
		t.Errorf("expected 2 anon-only route findings, got %d", findingCount)
	}
}

func TestAnalyzeVariance_AuthOnlyRoutes_NoFindings(t *testing.T) {
	variance := &AuthStateVariance{
		AuthOnlyURLs:  []string{"https://example.com/dashboard", "https://example.com/settings"},
		AnonOnlyURLs:  []string{},
		SharedURLs:    []string{"https://example.com/"},
		AnonOnlyForms: make(map[string]FormSummary),
		AuthOnlyForms: make(map[string]FormSummary),
		AnonPageCount: 1,
		AuthPageCount: 3,
	}

	result := AnalyzeVariance(variance, "scan-1")

	// Auth-only routes are informational — observations but NO findings
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for normal auth-only routes, got %d", len(result.Findings))
	}
	// But observations should exist
	if len(result.Observations) < 2 {
		t.Errorf("expected at least 2 observations for auth-only routes, got %d", len(result.Observations))
	}
}

func TestAnalyzeVariance_AnonOnlyForms_GenerateFindings(t *testing.T) {
	variance := &AuthStateVariance{
		AnonOnlyURLs: []string{},
		AuthOnlyURLs: []string{},
		SharedURLs:   []string{"https://example.com/"},
		AnonOnlyForms: map[string]FormSummary{
			"https://example.com/hidden-admin": {
				Count:   1,
				Actions: []string{"/reset-all"},
				Methods: []string{"POST"},
			},
		},
		AuthOnlyForms: make(map[string]FormSummary),
		AnonPageCount: 2,
		AuthPageCount: 2,
	}

	result := AnalyzeVariance(variance, "scan-1")

	// Anon-only forms are HIGH severity
	found := false
	for _, f := range result.Findings {
		if f.Severity == "high" && f.Category == "access_control" {
			found = true
		}
	}
	if !found {
		t.Error("expected high-severity finding for anon-only form")
	}
}

func TestAnalyzeVariance_SurfaceExpansion_Observation(t *testing.T) {
	// Auth expands surface by >= 2x with >= 5 auth-only routes
	variance := &AuthStateVariance{
		AuthOnlyURLs: []string{
			"https://example.com/a", "https://example.com/b",
			"https://example.com/c", "https://example.com/d",
			"https://example.com/e",
		},
		AnonOnlyURLs:  []string{},
		SharedURLs:    []string{"https://example.com/"},
		AnonOnlyForms: make(map[string]FormSummary),
		AuthOnlyForms: make(map[string]FormSummary),
		AnonPageCount: 3,
		AuthPageCount: 8,
	}

	result := AnalyzeVariance(variance, "scan-1")

	foundExpansion := false
	for _, obs := range result.Observations {
		if obs.Type == ObservationType(VarSurfaceExpansion) {
			foundExpansion = true
		}
	}
	if !foundExpansion {
		t.Error("expected surface expansion observation")
	}
}

func TestAnalyzeVariance_SurfaceExpansion_BelowThreshold(t *testing.T) {
	variance := &AuthStateVariance{
		AuthOnlyURLs:  []string{"https://example.com/a", "https://example.com/b"},
		AnonOnlyURLs:  []string{},
		SharedURLs:    []string{"https://example.com/"},
		AnonOnlyForms: make(map[string]FormSummary),
		AuthOnlyForms: make(map[string]FormSummary),
		AnonPageCount: 5,
		AuthPageCount: 7,
	}

	result := AnalyzeVariance(variance, "scan-1")

	for _, obs := range result.Observations {
		if obs.Type == ObservationType(VarSurfaceExpansion) {
			t.Error("should not trigger surface expansion below 2x threshold")
		}
	}
}

func TestAnalyzeVariance_EmptyVariance(t *testing.T) {
	variance := &AuthStateVariance{
		AnonOnlyForms: make(map[string]FormSummary),
		AuthOnlyForms: make(map[string]FormSummary),
	}

	result := AnalyzeVariance(variance, "scan-1")

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for empty variance, got %d", len(result.Findings))
	}
	if len(result.Observations) != 0 {
		t.Errorf("expected 0 observations for empty variance, got %d", len(result.Observations))
	}
}

func TestAnalyzeVariance_DeterministicFingerprints(t *testing.T) {
	variance := &AuthStateVariance{
		AnonOnlyURLs:  []string{"https://example.com/debug"},
		AuthOnlyURLs:  []string{},
		SharedURLs:    []string{},
		AnonOnlyForms: make(map[string]FormSummary),
		AuthOnlyForms: make(map[string]FormSummary),
	}

	r1 := AnalyzeVariance(variance, "scan-1")
	r2 := AnalyzeVariance(variance, "scan-1")

	if len(r1.Findings) == 0 || len(r2.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if r1.Findings[0].Evidence.SHA256 != r2.Findings[0].Evidence.SHA256 {
		t.Error("fingerprints should be deterministic for same input")
	}
}
