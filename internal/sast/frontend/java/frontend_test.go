package java

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/engine"
)

// Chunk SAST-2 end-to-end: parse real .java source files, run the existing
// rule engine, and assert that the emitted findings match the SAST-1
// fixture-based expectations. This is the chunk's main deliverable — it
// proves that the Java frontend produces IR the engine can analyze without
// any special casing.

type expectation struct {
	file           string
	expectFinding  bool
	expectedLine   int
	expectedRuleID string
	titleContains  string
}

var cryptoCases = []expectation{
	{
		file:           "WeakCryptoDES.java",
		expectFinding:  true,
		expectedLine:   11,
		expectedRuleID: "SC-JAVA-CRYPTO-001",
		titleContains:  "DES",
	},
	{
		file:          "StrongCryptoAES.java",
		expectFinding: false,
	},
	{
		file:           "WeakHashMD5.java",
		expectFinding:  true,
		expectedLine:   11,
		expectedRuleID: "SC-JAVA-CRYPTO-001",
		titleContains:  "MD5",
	},
	{
		file:           "ECBModeViolation.java",
		expectFinding:  true,
		expectedLine:   12,
		expectedRuleID: "SC-JAVA-CRYPTO-001",
		titleContains:  "ECB",
	},
	{
		file:          "NonLiteralCipherArg.java",
		expectFinding: false,
	},
}

func TestRealJavaCryptoFixtures(t *testing.T) {
	eng, err := engine.NewFromBuiltins()
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	for _, tc := range cryptoCases {
		t.Run(tc.file, func(t *testing.T) {
			mod, err := ParseFile(filepath.Join("testdata", tc.file), filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			findings := eng.Analyze(mod)

			if !tc.expectFinding {
				if len(findings) != 0 {
					t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
				}
				return
			}

			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.RuleID != tc.expectedRuleID {
				t.Errorf("rule_id: got %q, want %q", f.RuleID, tc.expectedRuleID)
			}
			if f.Line != tc.expectedLine {
				t.Errorf("line: got %d, want %d", f.Line, tc.expectedLine)
			}
			if tc.titleContains != "" && !strings.Contains(f.Title, tc.titleContains) {
				t.Errorf("title %q does not contain %q", f.Title, tc.titleContains)
			}
			if f.Severity != "high" {
				t.Errorf("severity: got %q", f.Severity)
			}
			if f.Confidence < 0.9 || f.Confidence > 1.0 {
				t.Errorf("confidence out of expected range: %v", f.Confidence)
			}
			if len(f.Evidence) != 1 {
				t.Errorf("evidence steps: got %d, want 1", len(f.Evidence))
			}
			if f.Evidence[0].Line != tc.expectedLine {
				t.Errorf("evidence line: got %d, want %d", f.Evidence[0].Line, tc.expectedLine)
			}
			if f.Fingerprint == "" || len(f.Fingerprint) != 64 {
				t.Errorf("fingerprint: %q", f.Fingerprint)
			}
		})
	}
}

// TestMixedCryptoBatchRealFile verifies that when a real Java file contains
// three crypto calls but only one is weak, the engine emits exactly one
// finding and points at the right line. This is the "module-level filter"
// test using real source.
func TestMixedCryptoBatchRealFile(t *testing.T) {
	eng, err := engine.NewFromBuiltins()
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	mod, err := ParseFile("testdata/MixedCryptoBatch.java", "testdata/MixedCryptoBatch.java")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	findings := eng.Analyze(mod)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !strings.Contains(f.Title, "DES") {
		t.Errorf("expected DES match, got title %q", f.Title)
	}
	if f.Line != 13 {
		t.Errorf("line: got %d, want 13 (the DES line in MixedCryptoBatch.java)", f.Line)
	}
	if f.Function != "com.example.MixedCryptoBatch.mix" {
		t.Errorf("function: got %q", f.Function)
	}
}

// TestFingerprintStableAcrossReparse verifies that running the full
// pipeline (parse → analyze) twice on the same source produces identical
// fingerprints. This is what allows the triage pipeline to preserve state
// across scans.
func TestFingerprintStableAcrossReparse(t *testing.T) {
	eng, _ := engine.NewFromBuiltins()
	mod1, _ := ParseFile("testdata/WeakCryptoDES.java", "testdata/WeakCryptoDES.java")
	mod2, _ := ParseFile("testdata/WeakCryptoDES.java", "testdata/WeakCryptoDES.java")
	f1 := eng.Analyze(mod1)[0].Fingerprint
	f2 := eng.Analyze(mod2)[0].Fingerprint
	if f1 != f2 {
		t.Errorf("fingerprint unstable: %s vs %s", f1, f2)
	}
}

// TestFingerprintDiffersFromSAST1Fixtures verifies that the real-parse
// finding and the SAST-1 hand-built-fixture finding do NOT share a
// fingerprint by accident — they're at different module paths, so their
// fingerprints must differ even though the code shape is identical. This
// catches any regression where module path is silently stripped.
func TestFingerprintDiffersByModulePath(t *testing.T) {
	eng, _ := engine.NewFromBuiltins()
	mod1, _ := ParseFile("testdata/WeakCryptoDES.java", "testdata/WeakCryptoDES.java")
	mod2, _ := ParseFile("testdata/WeakCryptoDES.java", "src/main/java/com/example/WeakCryptoDES.java")
	f1 := eng.Analyze(mod1)[0].Fingerprint
	f2 := eng.Analyze(mod2)[0].Fingerprint
	if f1 == f2 {
		t.Errorf("different module paths produced same fingerprint")
	}
}

// TestWalkJavaFiles verifies the filesystem walker skips build directories
// and picks up .java files anywhere else in the tree.
func TestWalkJavaFiles(t *testing.T) {
	files, err := WalkJavaFiles("testdata")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(files) < 5 {
		t.Errorf("expected at least 5 .java files under testdata, got %d", len(files))
	}
	for _, f := range files {
		if !strings.HasSuffix(f, ".java") {
			t.Errorf("walker returned non-java file: %s", f)
		}
	}
}
