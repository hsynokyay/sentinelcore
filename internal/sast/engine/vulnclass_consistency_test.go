package engine

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/csharp"
	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/java"
	jsfront "github.com/sentinelcore/sentinelcore/internal/sast/frontend/js"
	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/python"
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// TestAllFindingsHaveVulnClass is the Sprint 1.2 consistency invariant:
// after MigrateInPlace promotion + InferVulnClass heuristic fallback,
// EVERY finding emitted from the regression fixture must carry a
// non-empty VulnClass. An empty value would silently break the dedup
// pass (Deduplicate refuses to collapse empty-class findings, so a
// single forgotten rule could explode the duplicate count again).
//
// The test uses the canonical Sprint 1 corpus
// (tests/regression/fixtures/vulnerable-java-app) so the invariant is
// exercised against real rule output, not synthetic findings — this
// catches regressions in the loader / heuristic / build-site
// integration as a single end-to-end check.
func TestAllFindingsHaveVulnClass(t *testing.T) {
	root := regressionFixturePath(t, "vulnerable-java-app")

	eng, err := NewFromBuiltins()
	if err != nil {
		t.Fatalf("load builtins: %v", err)
	}

	modules := walkAndParse(t, root)
	if len(modules) == 0 {
		t.Fatalf("no modules parsed from %s — regression fixture moved or removed?", root)
	}

	findings := eng.AnalyzeAll(modules)
	if len(findings) == 0 {
		t.Fatalf("no findings from regression fixture — rules silently disabled?")
	}

	var missing []string
	for _, f := range findings {
		if f.VulnClass == "" {
			missing = append(missing,
				f.RuleID+" @ "+f.ModulePath+":"+itoa(f.Line))
		}
	}
	if len(missing) > 0 {
		t.Fatalf("findings without VulnClass: %d / %d\n%s",
			len(missing), len(findings), strings.Join(missing, "\n"))
	}
	t.Logf("OK: %d findings, all carry VulnClass", len(findings))
}

// regressionFixturePath resolves the absolute path of a fixture under
// tests/regression/fixtures from the test file's location, not the
// process's CWD — `go test` may run from anywhere depending on the
// invocation, and a relative "../../../tests/..." string would be
// fragile.
func regressionFixturePath(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("could not resolve test file location for fixture lookup")
	}
	// thisFile = .../internal/sast/engine/vulnclass_consistency_test.go
	// fixtures live at .../tests/regression/fixtures/<name>
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return filepath.Join(repoRoot, "tests", "regression", "fixtures", name)
}

// walkAndParse runs every per-language walker against root and returns
// the parsed IR modules. Mirrors what cmd/sast-worker does at runtime.
func walkAndParse(t *testing.T, root string) []*ir.Module {
	t.Helper()
	var modules []*ir.Module

	javaFiles, _ := java.WalkJavaFiles(root)
	for _, p := range javaFiles {
		rel, _ := filepath.Rel(root, p)
		m, err := java.ParseFile(p, rel)
		if err == nil {
			modules = append(modules, m)
		}
	}
	pyFiles, _ := python.WalkPythonFiles(root)
	for _, p := range pyFiles {
		rel, _ := filepath.Rel(root, p)
		m, err := python.ParseFile(p, rel)
		if err == nil {
			modules = append(modules, m)
		}
	}
	jsFiles, _ := jsfront.WalkJSFiles(root)
	for _, p := range jsFiles {
		rel, _ := filepath.Rel(root, p)
		m, err := jsfront.ParseFile(p, rel)
		if err == nil {
			modules = append(modules, m)
		}
	}
	csFiles, _ := csharp.WalkCSharpFiles(root)
	for _, p := range csFiles {
		rel, _ := filepath.Rel(root, p)
		m, err := csharp.ParseFile(p, rel)
		if err == nil {
			modules = append(modules, m)
		}
	}
	return modules
}
