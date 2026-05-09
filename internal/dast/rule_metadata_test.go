package dast

import (
	"strings"
	"testing"
)

// TestEveryGeneratorRuleHasMetadata catches the "I added a new probe but
// forgot to register its metadata" bug. The list mirrors what
// generator.go + passive_security.go emit.
func TestEveryGeneratorRuleHasMetadata(t *testing.T) {
	knownRules := []string{
		// active probes
		"DAST-SQLI-001", "DAST-XSS-001", "DAST-PT-001", "DAST-SSRF-001",
		"DAST-IDOR-001", "DAST-HI-001", "DAST-XXE-001", "DAST-NOSQL-001",
		"DAST-GRAPHQL-001", "DAST-JWT-001", "DAST-JWT-002", "DAST-CRLF-001",
		"DAST-OPENREDIR-001", "DAST-MASS-001", "DAST-PROTO-POL-001",
		// passive checks
		"DAST-HEAD-CSP-001", "DAST-HEAD-HSTS-001", "DAST-HEAD-XFO-001",
		"DAST-HEAD-XCTO-001", "DAST-HEAD-REFER-001", "DAST-HEAD-PERM-001",
		"DAST-HEAD-SERVER-001", "DAST-HEAD-XPOWERED-001",
		"DAST-COOKIE-SECURE-001", "DAST-COOKIE-HTTPONLY-001", "DAST-COOKIE-SAMESITE-001",
	}

	for _, ruleID := range knownRules {
		t.Run(ruleID, func(t *testing.T) {
			m, ok := ruleMetadataRegistry[ruleID]
			if !ok {
				t.Fatalf("rule %s missing from registry", ruleID)
			}
			if m.CWEID == 0 {
				t.Errorf("CWEID is 0 — must map to a CWE")
			}
			if m.OWASPCategory == "" {
				t.Errorf("OWASPCategory is empty — must map to an OWASP Top 10 category")
			}
			if m.Impact == "" {
				t.Errorf("Impact is empty")
			}
			if m.Remediation == "" {
				t.Errorf("Remediation is empty")
			}
			if len(m.References) == 0 {
				t.Errorf("no References supplied")
			}
			if len(m.Tags) == 0 {
				t.Errorf("no Tags supplied")
			}
		})
	}
}

func TestLookupRuleMetadata_AddsDastTagAndDefaultsRiskScore(t *testing.T) {
	m := LookupRuleMetadata("DAST-SQLI-001")
	hasDast := false
	for _, tag := range m.Tags {
		if tag == "dast" {
			hasDast = true
		}
	}
	if !hasDast {
		t.Errorf("LookupRuleMetadata must always include 'dast' tag, got %v", m.Tags)
	}
	if m.RiskScore != m.CVSSScore {
		t.Errorf("RiskScore should default to CVSSScore (%v), got %v", m.CVSSScore, m.RiskScore)
	}
}

func TestLookupRuleMetadata_UnknownRuleFallsBackSafely(t *testing.T) {
	m := LookupRuleMetadata("DAST-NOT-A-REAL-RULE")
	// Must not panic, must always return at least a dast tag.
	hasDast, hasUnmapped := false, false
	for _, t := range m.Tags {
		if t == "dast" {
			hasDast = true
		}
		if t == "unmapped" {
			hasUnmapped = true
		}
	}
	if !hasDast || !hasUnmapped {
		t.Errorf("unknown rule should be tagged dast+unmapped, got %v", m.Tags)
	}
	if m.CWEID != 0 || m.OWASPCategory != "" {
		t.Errorf("unknown rule must not invent classification")
	}
}

func TestRenderDescription_StructuresAllSections(t *testing.T) {
	m := LookupRuleMetadata("DAST-HEAD-CSP-001")
	out := m.RenderDescription("response missing Content-Security-Policy")

	for _, want := range []string{
		"**What was observed:**",
		"response missing Content-Security-Policy",
		"**Impact**",
		"**Remediation**",
		"**References**",
		"https://owasp.org/www-project-secure-headers/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered description missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestRenderDescription_OmitsObservedSectionWhenBlank(t *testing.T) {
	m := LookupRuleMetadata("DAST-SQLI-001")
	out := m.RenderDescription("")
	if strings.Contains(out, "**What was observed:**") {
		t.Errorf("blank match detail should suppress 'What was observed' section")
	}
	if !strings.Contains(out, "**Impact**") {
		t.Errorf("Impact section should still be present")
	}
}

func TestRuleMetadata_CVSSVectorPresentWhenScoreNonZero(t *testing.T) {
	for ruleID, m := range ruleMetadataRegistry {
		if m.CVSSScore > 0 && m.CVSSVector == "" {
			t.Errorf("%s: CVSSScore=%v but CVSSVector is empty", ruleID, m.CVSSScore)
		}
	}
}

func TestRuleMetadata_TagsAreLowercase(t *testing.T) {
	for ruleID, m := range ruleMetadataRegistry {
		for _, tag := range m.Tags {
			if tag != strings.ToLower(tag) {
				t.Errorf("%s: tag %q must be lowercase", ruleID, tag)
			}
		}
	}
}
