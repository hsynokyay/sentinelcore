package browser

import "testing"

func TestBrowserObservationRules_AllHaveCWE(t *testing.T) {
	for _, rule := range BrowserObservationRules {
		if rule.CWEID == 0 {
			t.Errorf("rule %s has no CWE ID", rule.ID)
		}
	}
}

func TestBrowserObservationRules_AllHaveCategory(t *testing.T) {
	for _, rule := range BrowserObservationRules {
		if rule.Category == "" {
			t.Errorf("rule %s has no category", rule.ID)
		}
	}
}

func TestBrowserObservationRules_UniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, rule := range BrowserObservationRules {
		if seen[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		seen[rule.ID] = true
	}
}

func TestBrowserObservationRules_ValidSeverity(t *testing.T) {
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, rule := range BrowserObservationRules {
		if !valid[rule.Severity] {
			t.Errorf("rule %s has invalid severity: %s", rule.ID, rule.Severity)
		}
	}
}

func TestBrowserObservationRules_ValidConfidence(t *testing.T) {
	valid := map[string]bool{"high": true, "medium": true, "low": true}
	for _, rule := range BrowserObservationRules {
		if !valid[rule.Confidence] {
			t.Errorf("rule %s has invalid confidence: %s", rule.ID, rule.Confidence)
		}
	}
}

func TestRuleByType(t *testing.T) {
	rule := RuleByType(ObsMissingCSRF)
	if rule == nil {
		t.Fatal("expected rule for missing CSRF")
	}
	if rule.ID != "BROWSER-001" {
		t.Errorf("wrong rule ID: %s", rule.ID)
	}
	if rule.CWEID != 352 {
		t.Errorf("wrong CWE: %d", rule.CWEID)
	}

	unknown := RuleByType(ObservationType("nonexistent"))
	if unknown != nil {
		t.Error("expected nil for unknown type")
	}
}

func TestObservation_Fields(t *testing.T) {
	obs := Observation{
		Type:       ObsInsecureCookie,
		URL:        "https://example.com",
		Detail:     "Cookie 'session' missing Secure flag",
		Confidence: "high",
		Severity:   "medium",
		CWEID:      614,
		RuleID:     "BROWSER-002",
	}
	if obs.CWEID != 614 {
		t.Error("wrong CWE")
	}
}
