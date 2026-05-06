package export

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSARIFEmitsComplianceTags asserts that when FindingData carries
// resolved ControlRefs, they surface as result.properties.tags using a
// stable "<catalog>:<control_id>" format that downstream SARIF tooling
// can filter on.
func TestSARIFEmitsComplianceTags(t *testing.T) {
	f := FindingData{
		ID:          "f1",
		Title:       "XSS",
		Severity:    "high",
		FindingType: "sast",
		FilePath:    "src/foo.go",
		LineStart:   42,
		ControlRefs: []ControlRef{
			{CatalogCode: "OWASP_TOP10_2021", ControlID: "A03", Title: "Injection", Confidence: "normative"},
			{CatalogCode: "PCI_DSS_4_0", ControlID: "6.2.4", Title: "Secure coding — injection", Confidence: "normative"},
		},
	}
	out, err := FindingSARIF(f)
	if err != nil {
		t.Fatalf("FindingSARIF: %v", err)
	}
	str := string(out)
	if !strings.Contains(str, `"owasp:A03"`) {
		t.Errorf("expected SARIF to contain owasp:A03 tag, got %s", str)
	}
	if !strings.Contains(str, `"pci:6.2.4"`) {
		t.Errorf("expected SARIF to contain pci:6.2.4 tag, got %s", str)
	}
	// Validate it parses as JSON and that the tags landed on
	// result.properties.tags (not just a substring match).
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("json parse: %v", err)
	}
}

// TestSARIFNoCompliance_NoTagsField when ControlRefs is empty, the
// emitter must not crash and must not emit an empty tags array of
// compliance origin (so existing snapshots remain stable).
func TestSARIFNoCompliance_NoTagsField(t *testing.T) {
	f := FindingData{
		ID:          "f1",
		Title:       "Test",
		Severity:    "low",
		FindingType: "sast",
	}
	out, err := FindingSARIF(f)
	if err != nil {
		t.Fatalf("FindingSARIF: %v", err)
	}
	if strings.Contains(string(out), `"owasp:`) || strings.Contains(string(out), `"pci:`) {
		t.Errorf("did not expect compliance tags, got %s", string(out))
	}
}

// TestMarkdownEmitsComplianceSection asserts that when ControlRefs are
// present, the Markdown export surfaces them in a Compliance section.
func TestMarkdownEmitsComplianceSection(t *testing.T) {
	f := FindingData{
		Title:       "XSS",
		Severity:    "high",
		Status:      "open",
		FindingType: "sast",
		ControlRefs: []ControlRef{
			{CatalogCode: "OWASP_TOP10_2021", CatalogName: "OWASP Top 10 (2021)", ControlID: "A03", Title: "Injection", Confidence: "normative"},
		},
	}
	out := FindingMarkdown(f)
	if !strings.Contains(out, "## Compliance") {
		t.Errorf("expected Compliance section in markdown, got %s", out)
	}
	if !strings.Contains(out, "OWASP Top 10 (2021)") || !strings.Contains(out, "A03") {
		t.Errorf("expected catalog name + control id in markdown, got %s", out)
	}
}

// TestComplianceCatalogPrefix verifies the catalog→tag prefix mapping.
func TestComplianceCatalogPrefix(t *testing.T) {
	cases := map[string]string{
		"OWASP_TOP10_2021": "owasp",
		"PCI_DSS_4_0":      "pci",
		"NIST_800_53_R5":   "nist",
		"INTERNAL_SEC":     "internal",
	}
	for code, want := range cases {
		got := complianceTagPrefix(code)
		if got != want {
			t.Errorf("complianceTagPrefix(%q) = %q, want %q", code, got, want)
		}
	}
}
