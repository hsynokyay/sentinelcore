package remediation

import "testing"

func TestLoadBuiltinRegistry(t *testing.T) {
	r, err := LoadBuiltinRegistry()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if r.Count() < 40 {
		t.Fatalf("expected at least 40 packs, got %d", r.Count())
	}

	rules := []string{
		// Java SAST
		"SC-JAVA-SQL-001",
		"SC-JAVA-CMD-001",
		"SC-JAVA-PATH-001",
		"SC-JAVA-CRYPTO-001",
		"SC-JAVA-SECRET-001",
		// JS/TS SAST
		"SC-JS-XSS-001",
		"SC-JS-CMD-001",
		"SC-JS-PATH-001",
		"SC-JS-EVAL-001",
		"SC-JS-SECRET-001",
		"SC-JS-SQL-001",
		"SC-JS-SSRF-001",
		// Java expansion
		"SC-JAVA-SSRF-001",
		"SC-JAVA-REDIRECT-001",
		// Python SAST
		"SC-PY-CMD-001",
		"SC-PY-PATH-001",
		"SC-PY-EVAL-001",
		"SC-PY-SQL-001",
		"SC-PY-SECRET-001",
		"SC-PY-SSRF-001",
		// DAST
		"SC-DAST-CSRF-001",
		"SC-DAST-MIXED-001",
		"SC-DAST-AUTOCOMPLETE-001",
		"SC-DAST-INLINE-001",
		"SC-DAST-AUTHZ-001",
		"SC-DAST-XSS-001",
		"SC-DAST-SSRF-001",
		"SC-DAST-OPENREDIRECT-001",
		"SC-DAST-SECHEADERS-001",
		"SC-DAST-COOKIEFLAGS-001",
	}
	for _, ruleID := range rules {
		pack := r.Get(ruleID)
		if pack == nil {
			t.Errorf("missing pack for %s", ruleID)
			continue
		}
		if pack.Title == "" {
			t.Errorf("%s: empty title", ruleID)
		}
		if pack.Summary == "" {
			t.Errorf("%s: empty summary", ruleID)
		}
		if pack.WhyItMatters == "" {
			t.Errorf("%s: empty why_it_matters", ruleID)
		}
		if pack.HowToFix == "" {
			t.Errorf("%s: empty how_to_fix", ruleID)
		}
		if pack.UnsafeExample == "" {
			t.Errorf("%s: empty unsafe_example", ruleID)
		}
		if pack.SafeExample == "" {
			t.Errorf("%s: empty safe_example", ruleID)
		}
		if len(pack.VerificationChecklist) == 0 {
			t.Errorf("%s: empty verification_checklist", ruleID)
		}
		if len(pack.References) == 0 {
			t.Errorf("%s: empty references", ruleID)
		}
		// Security: examples must not contain actual secrets
		for _, forbidden := range []string{"sk-live-abcdef1234567890", "ProductionP@ssw0rd", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload"} {
			if contains(pack.SafeExample, forbidden) {
				t.Errorf("%s: safe_example contains a real-looking secret", ruleID)
			}
		}
	}

	// Unknown rule returns nil
	if r.Get("SC-JAVA-UNKNOWN-999") != nil {
		t.Errorf("unknown rule should return nil")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
