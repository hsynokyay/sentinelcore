package engine

import (
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// TestHardcodedSecretVulnerable: hardcoded API keys, passwords, and tokens
// in real Java source must produce findings.
func TestHardcodedSecretVulnerable(t *testing.T) {
	eng := mustBuildEngine(t)
	mod := mustParse(t, "HardcodedSecretVulnerable.java")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	secrets := filterRule(findings, "SC-JAVA-SECRET-001")

	if len(secrets) < 3 {
		t.Fatalf("expected at least 3 hardcoded secret findings, got %d.\nAll findings: %+v", len(secrets), findings)
	}

	// Verify classification.
	for _, f := range secrets {
		if f.Severity != "high" {
			t.Errorf("severity: got %q", f.Severity)
		}
		hasCWE := false
		for _, c := range f.CWE {
			if c == "CWE-798" || c == "CWE-259" {
				hasCWE = true
			}
		}
		if !hasCWE {
			t.Errorf("CWE list missing CWE-798 or CWE-259: %v", f.CWE)
		}
		if f.Confidence < 0.7 {
			t.Errorf("confidence too low for %q: %v", f.Title, f.Confidence)
		}
		if len(f.Evidence) < 1 {
			t.Errorf("missing evidence for %q", f.Title)
		}
	}

	// Verify evidence is redacted — no full secret should appear.
	for _, f := range secrets {
		for _, e := range f.Evidence {
			if strings.Contains(e.Description, "abcdef1234567890") {
				t.Errorf("evidence leaks full secret: %q", e.Description)
			}
			if strings.Contains(e.Description, "Super$ecretP@ss2024") {
				t.Errorf("evidence leaks full secret: %q", e.Description)
			}
		}
	}

	t.Logf("SUCCESS: %d hardcoded secret findings detected", len(secrets))
	for _, f := range secrets {
		t.Logf("  %s: %s (line %d, confidence %.2f)", f.RuleID, f.Title, f.Line, f.Confidence)
	}
}

// TestHardcodedSecretSafe: placeholder values, env lookups, and benign
// config strings must NOT produce findings.
func TestHardcodedSecretSafe(t *testing.T) {
	eng := mustBuildEngine(t)
	mod := mustParse(t, "HardcodedSecretSafe.java")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	secrets := filterRule(findings, "SC-JAVA-SECRET-001")

	if len(secrets) != 0 {
		t.Errorf("expected 0 hardcoded secret findings for safe file, got %d:", len(secrets))
		for _, f := range secrets {
			t.Logf("  FP: %s at line %d (confidence %.2f)", f.Title, f.Line, f.Confidence)
		}
	}
}

// TestAllFiveVulnClassesComplete verifies the full Java MVP slice: all five
// vulnerability classes fire together.
func TestAllFiveVulnClassesComplete(t *testing.T) {
	eng := mustBuildEngine(t)
	mods := []*ir.Module{
		mustParse(t, "SqlInjectionVulnerable.java"),
		mustParse(t, "CommandInjectionVulnerable.java"),
		mustParse(t, "PathTraversalVulnerable.java"),
		mustParse(t, "WeakCryptoDES.java"),
		mustParse(t, "HardcodedSecretVulnerable.java"),
	}

	findings := eng.AnalyzeAll(mods)
	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.RuleID] = true
	}

	expected := []string{
		"SC-JAVA-SQL-001",
		"SC-JAVA-CMD-001",
		"SC-JAVA-PATH-001",
		"SC-JAVA-CRYPTO-001",
		"SC-JAVA-SECRET-001",
	}
	for _, r := range expected {
		if !rules[r] {
			t.Errorf("missing rule %s in combined analysis. Found: %v", r, rules)
		}
	}
	t.Logf("SUCCESS: all 5 Java MVP vulnerability classes detected (%d total findings)", len(findings))
}

// TestSecretEntropyHeuristic verifies the entropy filter works.
func TestSecretEntropyHeuristic(t *testing.T) {
	if isHighEntropy("password123") {
		t.Error("'password123' should be low entropy")
	}
	if isHighEntropy("admin") {
		t.Error("'admin' should be low entropy")
	}
	if !isHighEntropy("sk-live-abcdef1234567890abcdef") {
		t.Error("'sk-live-abcdef1234567890abcdef' should be high entropy")
	}
	if !isHighEntropy("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Error("JWT-shaped token should be high entropy")
	}
}

// TestSecretRedaction verifies that redactSecret never exposes the full value.
func TestSecretRedaction(t *testing.T) {
	cases := map[string]string{
		"sk-live-abcdef1234567890": "\"sk-l…\" (24 chars)",
		"tiny":                     "\"****\"",
	}
	for input, want := range cases {
		got := redactSecret(input)
		if got != want {
			t.Errorf("redactSecret(%q) = %q, want %q", input, got, want)
		}
	}
}
