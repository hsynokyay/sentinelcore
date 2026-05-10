package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestManifest_LegacyRuleStillWorks: the legacy single-string "rule" form
// must continue to round-trip into a one-element Rules slice so existing
// manifest entries keep working without edits.
func TestManifest_LegacyRuleStillWorks(t *testing.T) {
	src := `{"id":"X-1","file":"a.java","class":"weak_crypto","expect":"positive","rule":"SC-JAVA-CRYPTO-001"}`
	var c Case
	if err := json.Unmarshal([]byte(src), &c); err != nil {
		t.Fatalf("legacy rule form failed to parse: %v", err)
	}
	want := []string{"SC-JAVA-CRYPTO-001"}
	if !reflect.DeepEqual(c.Rules, want) {
		t.Errorf("Rules = %v, want %v", c.Rules, want)
	}
}

// TestManifest_RuleAndRulesMutuallyExclusive: supplying both fields is
// always a manifest authoring mistake — the loader must reject it loudly
// rather than silently picking one.
func TestManifest_RuleAndRulesMutuallyExclusive(t *testing.T) {
	src := `{"id":"X-1","file":"a.java","class":"hardcoded_secret","expect":"positive","rule":"SC-JAVA-SECRET-001","rules":["SC-JAVA-JWT-003"]}`
	var c Case
	err := json.Unmarshal([]byte(src), &c)
	if err == nil {
		t.Fatalf("expected error for rule+rules together, got nil (parsed: %+v)", c)
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error message should mention mutual exclusion, got: %v", err)
	}
}

// TestManifest_EmptyRulesArrayRejected: a present-but-empty "rules": []
// would silently turn the entry into an unsatisfiable test (no rule_id
// can ever match) — reject at load time so authors notice.
func TestManifest_EmptyRulesArrayRejected(t *testing.T) {
	src := `{"id":"X-1","file":"a.java","class":"hardcoded_secret","expect":"positive","rules":[]}`
	var c Case
	err := json.Unmarshal([]byte(src), &c)
	if err == nil {
		t.Fatalf("expected error for empty rules array, got nil (parsed: %+v)", c)
	}
	if !strings.Contains(err.Error(), "non-empty") {
		t.Errorf("error message should mention non-empty requirement, got: %v", err)
	}
}

// TestManifest_NeitherRuleNorRulesRejected: an entry missing both fields
// has no expectation at all and should also be rejected — same reasoning
// as the empty-array case.
func TestManifest_NeitherRuleNorRulesRejected(t *testing.T) {
	src := `{"id":"X-1","file":"a.java","class":"hardcoded_secret","expect":"positive"}`
	var c Case
	if err := json.Unmarshal([]byte(src), &c); err == nil {
		t.Fatalf("expected error when neither rule nor rules supplied, got nil")
	}
}

// TestManifest_RulesArrayAcceptsAny is the integration check: the
// any-match semantics must turn a finding from EITHER listed rule_id
// into a TP. We point a temp manifest at the real BenchSecret003.java
// fixture (which post-Sprint-1.2 fires SC-JAVA-JWT-003, not
// SC-JAVA-SECRET-001) and assert the case scores TP — the regression
// the contract change exists to fix.
func TestManifest_RulesArrayAcceptsAny(t *testing.T) {
	corpusDir := "corpus"
	if _, err := os.Stat(filepath.Join(corpusDir, "secret/positive/BenchSecret003.java")); err != nil {
		t.Skipf("corpus not available: %v", err)
	}

	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "manifest.json")
	manifest := `{
	  "version": "test",
	  "description": "any-match contract test",
	  "cases": [
	    {"id":"JWT-ANY-1","file":"secret/positive/BenchSecret003.java","class":"hardcoded_secret","expect":"positive","rules":["SC-JAVA-SECRET-001","SC-JAVA-JWT-003"]}
	  ]
	}`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	result, err := Run(corpusDir, manifestPath)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(result.Cases) != 1 {
		t.Fatalf("expected 1 case result, got %d", len(result.Cases))
	}
	got := result.Cases[0]
	if got.Outcome != "TP" {
		t.Fatalf("any-match should classify as TP; got %s with %d findings", got.Outcome, len(got.Findings))
	}
	// Sanity: the surviving finding must come from one of the listed rules.
	if len(got.Findings) == 0 {
		t.Fatalf("TP outcome but no relevant findings recorded")
	}
	allowed := map[string]bool{"SC-JAVA-SECRET-001": true, "SC-JAVA-JWT-003": true}
	for _, f := range got.Findings {
		if !allowed[f.RuleID] {
			t.Errorf("relevantFindings contains unexpected rule_id %q", f.RuleID)
		}
	}
}
