package python

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/engine"
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

func mustEngine(t *testing.T) *engine.Engine {
	t.Helper()
	eng, err := engine.NewFromBuiltins()
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func mustParsePy(t *testing.T, filename string) *ir.Module {
	t.Helper()
	mod, err := ParseFile(filepath.Join("testdata", filename), "testdata/"+filename)
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

func filterByRule(findings []engine.Finding, ruleID string) []engine.Finding {
	var out []engine.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func ruleIDs(findings []engine.Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

// --- Parser tests ---

func TestPythonParserFunctionDetection(t *testing.T) {
	src := []byte("import os\n\ndef handle(request):\n    cmd = request.args.get(\"cmd\")\n    os.system(cmd)\n")
	mod := ParseSource("test.py", src)
	if mod.Language != "python" {
		t.Errorf("language: %q", mod.Language)
	}
	var found bool
	for _, c := range mod.Classes {
		for _, m := range c.Methods {
			if m.Name == "handle" {
				found = true
			}
		}
	}
	if !found {
		t.Error("handle function not found")
	}
}

func TestPythonImportDetection(t *testing.T) {
	src := []byte("import os\nfrom subprocess import call, run\nfrom flask import request\n")
	mod := ParseSource("test.py", src)
	if len(mod.Imports) < 3 {
		t.Errorf("expected >= 3 imports, got %d", len(mod.Imports))
	}
}

// --- Detection tests ---

func TestPyCmdInjection(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParsePy(t, "cmd-injection-vuln.py")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	cmd := filterByRule(findings, "SC-PY-CMD-001")
	if len(cmd) < 1 {
		t.Fatalf("expected cmd injection, got %d. Rules: %v", len(cmd), ruleIDs(findings))
	}
	t.Logf("SUCCESS: Python cmd injection detected (%d)", len(cmd))
}

func TestPyPathTraversal(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParsePy(t, "path-traversal-vuln.py")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	path := filterByRule(findings, "SC-PY-PATH-001")
	if len(path) < 1 {
		t.Fatalf("expected path traversal, got %d. Rules: %v", len(path), ruleIDs(findings))
	}
	t.Logf("SUCCESS: Python path traversal detected (%d)", len(path))
}

func TestPyEvalInjection(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParsePy(t, "eval-vuln.py")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	ev := filterByRule(findings, "SC-PY-EVAL-001")
	if len(ev) < 1 {
		t.Fatalf("expected eval injection, got %d. Rules: %v", len(ev), ruleIDs(findings))
	}
	t.Logf("SUCCESS: Python eval injection detected (%d)", len(ev))
}

func TestPySQLInjection(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParsePy(t, "sqli-vuln.py")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	sqli := filterByRule(findings, "SC-PY-SQL-001")
	if len(sqli) < 1 {
		t.Fatalf("expected SQL injection, got %d. Rules: %v", len(sqli), ruleIDs(findings))
	}
	t.Logf("SUCCESS: Python SQL injection detected (%d)", len(sqli))
}

func TestPyHardcodedSecret(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParsePy(t, "secret-vuln.py")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	sec := filterByRule(findings, "SC-PY-SECRET-001")
	if len(sec) < 1 {
		t.Fatalf("expected secret, got %d. Rules: %v", len(sec), ruleIDs(findings))
	}
	t.Logf("SUCCESS: Python secret detected (%d)", len(sec))
}

func TestPySSRF(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParsePy(t, "ssrf-vuln.py")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	ssrf := filterByRule(findings, "SC-PY-SSRF-001")
	if len(ssrf) < 1 {
		t.Fatalf("expected SSRF, got %d. Rules: %v", len(ssrf), ruleIDs(findings))
	}
	t.Logf("SUCCESS: Python SSRF detected (%d)", len(ssrf))
}

func TestPySafeFilesNoFindings(t *testing.T) {
	eng := mustEngine(t)
	safeFiles := []string{"cmd-injection-safe.py", "path-traversal-safe.py", "eval-safe.py", "sqli-safe.py", "secret-safe.py", "ssrf-safe.py", "deser-safe.py", "deser-yaml-safe.py", "weak-crypto-safe.py", "redirect-safe.py"}
	for _, f := range safeFiles {
		mod := mustParsePy(t, f)
		findings := eng.AnalyzeAll([]*ir.Module{mod})
		var pyFindings []engine.Finding
		for _, finding := range findings {
			if strings.HasPrefix(finding.RuleID, "SC-PY-") {
				pyFindings = append(pyFindings, finding)
			}
		}
		if len(pyFindings) != 0 {
			t.Errorf("expected 0 Python findings for %s, got %d: %v", f, len(pyFindings), ruleIDs(pyFindings))
		}
	}
}

func TestPyWalkFiles(t *testing.T) {
	files, err := WalkPythonFiles("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 10 {
		t.Errorf("expected >= 10 .py files, got %d", len(files))
	}
}
