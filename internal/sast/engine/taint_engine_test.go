package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/java"
)

// TestSqlInjectionVulnerable is the Chunk SAST-3 success-criteria test:
// a real Java file with request.getParameter → string concat → executeQuery
// must produce a finding with a correct evidence chain.
func TestSqlInjectionVulnerable(t *testing.T) {
	eng := mustBuildEngine(t)
	mod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "SqlInjectionVulnerable.java"),
		"testdata/SqlInjectionVulnerable.java",
	)
	if err != nil {
		t.Fatal(err)
	}

	findings := eng.Analyze(mod)

	// Filter to SQLi findings only (the weak-crypto rule shouldn't fire
	// because there's no Cipher.getInstance in this file).
	var sqli []Finding
	for _, f := range findings {
		if f.RuleID == "SC-JAVA-SQL-001" {
			sqli = append(sqli, f)
		}
	}

	if len(sqli) != 1 {
		t.Fatalf("expected exactly 1 SQL injection finding, got %d.\nAll findings: %+v", len(sqli), findings)
	}

	f := sqli[0]
	// Classification
	if f.Severity != "critical" {
		t.Errorf("severity: got %q, want critical", f.Severity)
	}
	hasCWE89 := false
	for _, c := range f.CWE {
		if c == "CWE-89" {
			hasCWE89 = true
		}
	}
	if !hasCWE89 {
		t.Errorf("CWE list does not contain CWE-89: %v", f.CWE)
	}
	if f.Confidence < 0.8 {
		t.Errorf("confidence too low: %v", f.Confidence)
	}

	// Function
	if !strings.Contains(f.Function, "handleRequest") {
		t.Errorf("function: %q", f.Function)
	}

	// Evidence chain: must have at least 2 steps (source + sink).
	if len(f.Evidence) < 2 {
		t.Fatalf("evidence steps: got %d, want >= 2. Evidence: %+v", len(f.Evidence), f.Evidence)
	}
	sourceStep := f.Evidence[0]
	sinkStep := f.Evidence[len(f.Evidence)-1]
	if !strings.Contains(sourceStep.Description, "getParameter") {
		t.Errorf("source evidence should mention getParameter: %q", sourceStep.Description)
	}
	if !strings.Contains(sinkStep.Description, "executeQuery") {
		t.Errorf("sink evidence should mention executeQuery: %q", sinkStep.Description)
	}

	// Fingerprint
	if len(f.Fingerprint) != 64 {
		t.Errorf("fingerprint length: %d", len(f.Fingerprint))
	}

	t.Logf("SUCCESS: found SQLi at %s:%d → %s", f.ModulePath, f.Line, f.Title)
}

// TestSqlInjectionSafe verifies that PreparedStatement usage does not
// produce a SQL injection finding. If this test fails, the taint engine
// is over-reporting.
func TestSqlInjectionSafe(t *testing.T) {
	eng := mustBuildEngine(t)
	mod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "SqlInjectionSafe.java"),
		"testdata/SqlInjectionSafe.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	findings := eng.Analyze(mod)
	for _, f := range findings {
		if f.RuleID == "SC-JAVA-SQL-001" {
			t.Errorf("false positive: SQL injection finding in safe code: %+v", f)
		}
	}
}

// TestSqlInjectionMixed verifies that when a class has one vulnerable and
// one safe method, exactly the vulnerable method is flagged.
func TestSqlInjectionMixed(t *testing.T) {
	eng := mustBuildEngine(t)
	mod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "SqlInjectionMixed.java"),
		"testdata/SqlInjectionMixed.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	findings := eng.Analyze(mod)

	var sqli []Finding
	for _, f := range findings {
		if f.RuleID == "SC-JAVA-SQL-001" {
			sqli = append(sqli, f)
		}
	}
	if len(sqli) != 1 {
		t.Fatalf("expected 1 SQLi finding (vulnerable method only), got %d: %+v", len(sqli), sqli)
	}
	if !strings.Contains(sqli[0].Function, "vulnerableSearch") {
		t.Errorf("finding should be in vulnerableSearch, got function=%q", sqli[0].Function)
	}
}

// TestWeakCryptoStillWorksWithTaintEngine verifies the AST-local weak
// crypto rule continues to fire correctly now that the taint engine is also
// active. The two analysis paths must coexist.
func TestWeakCryptoStillWorksWithTaintEngine(t *testing.T) {
	eng := mustBuildEngine(t)
	mod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "WeakCryptoDES.java"),
		"testdata/WeakCryptoDES.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	findings := eng.Analyze(mod)
	var crypto []Finding
	for _, f := range findings {
		if f.RuleID == "SC-JAVA-CRYPTO-001" {
			crypto = append(crypto, f)
		}
	}
	if len(crypto) != 1 {
		t.Fatalf("weak crypto finding should still work, got %d", len(crypto))
	}
}

func mustBuildEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := NewFromBuiltins()
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	return eng
}

func javaTestdata() string {
	return filepath.Join("..", "frontend", "java", "testdata")
}
