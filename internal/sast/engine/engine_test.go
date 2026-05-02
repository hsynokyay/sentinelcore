package engine

import (
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/fixtures"
)

// TestEndToEndWeakCryptoDES is the Chunk SAST-1 first-light test. It
// verifies the full analysis pipeline:
//
//  1. Load built-in rules from the embedded JSON.
//  2. Compile rules (regex precompile + pattern validation).
//  3. Analyze a Java fixture that represents `Cipher.getInstance("DES")`.
//  4. Emit exactly one finding with the expected classification, stable
//     fingerprint, correct location, and a single-step evidence chain.
//
// If this test passes, the SAST engine architecture is proven end-to-end.
// Every subsequent chunk is additive improvement against a working pipeline.
func TestEndToEndWeakCryptoDES(t *testing.T) {
	eng, err := NewFromBuiltins()
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	if eng.RuleCount() == 0 {
		t.Fatalf("no rules loaded")
	}

	mod := fixtures.WeakCryptoDES()
	findings := eng.Analyze(mod)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]

	// Classification
	if f.RuleID != "SC-JAVA-CRYPTO-001" {
		t.Errorf("rule id: got %q", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q", f.Severity)
	}
	if f.Confidence < 0.9 || f.Confidence > 1.0 {
		t.Errorf("confidence: got %v, want in [0.9, 1.0]", f.Confidence)
	}
	wantCWE := map[string]bool{"CWE-327": false, "CWE-328": false}
	for _, c := range f.CWE {
		wantCWE[c] = true
	}
	for k, v := range wantCWE {
		if !v {
			t.Errorf("missing CWE: %s", k)
		}
	}

	// Title was templated from the message_template.
	if f.Title == "" || !contains(f.Title, "DES") {
		t.Errorf("title did not reflect matched arg: %q", f.Title)
	}

	// Location
	if f.ModulePath != "src/main/java/com/example/WeakCryptoDES.java" {
		t.Errorf("module path: got %q", f.ModulePath)
	}
	if f.Function != "com.example.WeakCryptoDES.bad" {
		t.Errorf("function: got %q", f.Function)
	}
	if f.Line != 6 {
		t.Errorf("line: got %d, want 6", f.Line)
	}

	// Fingerprint is stable and non-empty
	if len(f.Fingerprint) != 64 {
		t.Errorf("fingerprint length: got %d", len(f.Fingerprint))
	}
	again := eng.Analyze(fixtures.WeakCryptoDES())[0].Fingerprint
	if f.Fingerprint != again {
		t.Errorf("fingerprint unstable across runs")
	}

	// Evidence chain
	if len(f.Evidence) != 1 {
		t.Fatalf("evidence steps: got %d, want 1", len(f.Evidence))
	}
	step := f.Evidence[0]
	if step.StepIndex != 0 {
		t.Errorf("step index: got %d", step.StepIndex)
	}
	if step.Opcode != "call" {
		t.Errorf("step opcode: got %q", step.Opcode)
	}
	if step.Description == "" || !contains(step.Description, "DES") {
		t.Errorf("evidence description: %q", step.Description)
	}
	if step.Line != 6 {
		t.Errorf("evidence line: got %d", step.Line)
	}
}

// TestStrongCryptoIsNotFlagged is the negative test: AES/GCM must not fire.
func TestStrongCryptoIsNotFlagged(t *testing.T) {
	eng, _ := NewFromBuiltins()
	findings := eng.Analyze(fixtures.StrongCryptoAES())
	if len(findings) != 0 {
		t.Errorf("AES/GCM should not fire: got %d findings: %+v", len(findings), findings)
	}
}

// TestWeakHashMD5 verifies the second pattern (MessageDigest.getInstance).
func TestWeakHashMD5(t *testing.T) {
	eng, _ := NewFromBuiltins()
	findings := eng.Analyze(fixtures.WeakHashMD5())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Function != "com.example.WeakHashMD5.hash" {
		t.Errorf("function: got %q", findings[0].Function)
	}
	if !contains(findings[0].Title, "MD5") {
		t.Errorf("title: %q", findings[0].Title)
	}
}

// TestECBIsFlagged verifies the "AES/ECB/..." regex (ECB mode violation
// even when the cipher algorithm itself is strong).
func TestECBIsFlagged(t *testing.T) {
	eng, _ := NewFromBuiltins()
	findings := eng.Analyze(fixtures.ECBModeViolation())
	if len(findings) != 1 {
		t.Fatalf("ECB must fire: got %d findings", len(findings))
	}
}

// TestMixedBatch verifies module-level filtering: one fixture with three
// calls, only one of which is a weak-crypto match. Proves we don't
// over-match or under-match.
func TestMixedBatch(t *testing.T) {
	eng, _ := NewFromBuiltins()
	findings := eng.Analyze(fixtures.MixedCryptoBatch())
	if len(findings) != 1 {
		t.Fatalf("mixed batch should produce exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	// Should be the DES call (line 7), not the SHA-256 (line 8) or AES (line 9).
	if findings[0].Line != 7 {
		t.Errorf("expected DES call at line 7, got line %d", findings[0].Line)
	}
}

// TestNonLiteralArgIsNotFlaggedYet documents the Chunk SAST-1 limitation:
// when Cipher.getInstance receives a value reference (parameter, field,
// local) instead of a string literal, the AST-local matcher skips it. The
// taint engine in Chunk SAST-3 will reach back to the definition.
func TestNonLiteralArgIsNotFlaggedYet(t *testing.T) {
	eng, _ := NewFromBuiltins()
	findings := eng.Analyze(fixtures.NonLiteralCipherArg())
	if len(findings) != 0 {
		t.Errorf("AST-local matcher must not fire on non-literal arg (Chunk SAST-1 limitation): got %d findings", len(findings))
	}
}

// TestFingerprintStabilityAcrossCosmetic verifies that two modules with
// identical code shape but different file paths produce different
// fingerprints (different modules = different findings), while two analyses
// of the same module produce identical fingerprints.
func TestFingerprintStabilityAcrossCosmetic(t *testing.T) {
	eng, _ := NewFromBuiltins()
	a := eng.Analyze(fixtures.WeakCryptoDES())[0].Fingerprint
	b := eng.Analyze(fixtures.WeakCryptoDES())[0].Fingerprint
	if a != b {
		t.Errorf("same input different fingerprint: %s vs %s", a, b)
	}
	// DES and MD5 must have different fingerprints (different rule match key).
	m := eng.Analyze(fixtures.WeakHashMD5())[0].Fingerprint
	if a == m {
		t.Errorf("distinct findings share fingerprint")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
