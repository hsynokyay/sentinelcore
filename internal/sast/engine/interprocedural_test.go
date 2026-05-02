package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/java"
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// TestCrossFunctionSqli is the Chunk SAST-4 success-criteria test:
// getParameter → buildQuery(id) → executeQuery(sql) must fire across the
// call boundary within the same class.
func TestCrossFunctionSqli(t *testing.T) {
	eng := mustBuildEngine(t)
	mod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "CrossFunctionSqli.java"),
		"testdata/CrossFunctionSqli.java",
	)
	if err != nil {
		t.Fatal(err)
	}

	findings := eng.AnalyzeAll([]*ir.Module{mod})
	sqli := filterRule(findings, "SC-JAVA-SQL-001")

	if len(sqli) < 1 {
		t.Fatalf("expected at least 1 cross-function SQL injection finding, got %d.\nAll findings: %+v", len(sqli), findings)
	}
	f := sqli[0]
	if !strings.Contains(f.Function, "handleRequest") && !strings.Contains(f.Function, "buildQuery") {
		t.Errorf("finding function: %q — expected to involve handleRequest or buildQuery", f.Function)
	}
	if len(f.Evidence) < 2 {
		t.Errorf("evidence chain too short for inter-proc flow: %d steps", len(f.Evidence))
	}
	t.Logf("SUCCESS: cross-function SQLi detected at %s:%d with %d evidence steps", f.ModulePath, f.Line, len(f.Evidence))
}

// TestCrossFunctionSanitized verifies that when tainted input flows through
// a helper that uses PreparedStatement (sanitizer), no finding is produced.
func TestCrossFunctionSanitized(t *testing.T) {
	eng := mustBuildEngine(t)
	mod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "CrossFunctionSanitized.java"),
		"testdata/CrossFunctionSanitized.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	sqli := filterRule(findings, "SC-JAVA-SQL-001")
	if len(sqli) != 0 {
		t.Errorf("expected no SQLi finding (sanitized in callee), got %d: %+v", len(sqli), sqli)
	}
}

// TestCrossClassSqli verifies that taint flows across class boundaries when
// two files are analyzed together.
func TestCrossClassSqli(t *testing.T) {
	eng := mustBuildEngine(t)

	// Parse both files.
	callerMod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "CrossClassSqli.java"),
		"testdata/CrossClassSqli.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	helperMod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "SqlHelper.java"),
		"testdata/SqlHelper.java",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Analyze together — the helper's summary should be available when the
	// caller is analyzed. Order: helper first so its summary builds before
	// the caller needs it.
	findings := eng.AnalyzeAll([]*ir.Module{helperMod, callerMod})
	sqli := filterRule(findings, "SC-JAVA-SQL-001")

	if len(sqli) < 1 {
		t.Fatalf("expected at least 1 cross-class SQL injection finding, got %d.\nAll findings: %+v", len(sqli), findings)
	}
	t.Logf("SUCCESS: cross-class SQLi detected with %d finding(s)", len(sqli))
}

// TestIntraProcStillWorksWithInterProc ensures the SAST-3 intra-procedural
// tests still pass after the inter-procedural extensions.
func TestIntraProcStillWorksWithInterProc(t *testing.T) {
	eng := mustBuildEngine(t)
	mod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "SqlInjectionVulnerable.java"),
		"testdata/SqlInjectionVulnerable.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	sqli := filterRule(findings, "SC-JAVA-SQL-001")
	if len(sqli) != 1 {
		t.Errorf("expected 1 intra-proc SQLi finding, got %d", len(sqli))
	}
}

// TestDeduplication verifies that analyzing the same module twice via
// AnalyzeAll does not produce duplicate findings.
func TestDeduplication(t *testing.T) {
	eng := mustBuildEngine(t)
	mod, err := java.ParseFile(
		filepath.Join(javaTestdata(), "SqlInjectionVulnerable.java"),
		"testdata/SqlInjectionVulnerable.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	// Pass the same module twice — dedup must collapse to 1 finding.
	findings := eng.AnalyzeAll([]*ir.Module{mod, mod})
	sqli := filterRule(findings, "SC-JAVA-SQL-001")
	if len(sqli) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(sqli))
	}
}

func filterRule(findings []Finding, ruleID string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}
