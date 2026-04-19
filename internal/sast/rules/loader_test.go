package rules

import "testing"

func TestLoadBuiltins(t *testing.T) {
	rs, err := LoadBuiltins()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs) == 0 {
		t.Fatalf("expected at least one builtin rule")
	}

	var weakCrypto *Rule
	for _, r := range rs {
		if r.RuleID == "SC-JAVA-CRYPTO-001" {
			weakCrypto = r
			break
		}
	}
	if weakCrypto == nil {
		t.Fatalf("SC-JAVA-CRYPTO-001 not found in builtins")
	}
	if weakCrypto.Severity != "high" {
		t.Errorf("severity: got %q", weakCrypto.Severity)
	}
	if len(weakCrypto.CWE) == 0 {
		t.Errorf("CWE list is empty")
	}
	if weakCrypto.Detection.Kind != DetectionASTCall {
		t.Errorf("detection kind: got %q", weakCrypto.Detection.Kind)
	}
	if len(weakCrypto.Detection.Patterns) < 2 {
		t.Errorf("expected at least 2 patterns (Cipher + MessageDigest)")
	}
}

func TestCompileAll(t *testing.T) {
	rs, err := LoadBuiltins()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileAll(rs)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(compiled) != len(rs) {
		t.Fatalf("compiled count: got %d, want %d", len(compiled), len(rs))
	}
	for _, cr := range compiled {
		for i, p := range cr.Patterns {
			if len(p.ArgRegexes) != len(p.Source.ArgMatchesAny) {
				t.Errorf("rule %s pattern %d: %d compiled regex vs %d source", cr.Source.RuleID, i, len(p.ArgRegexes), len(p.Source.ArgMatchesAny))
			}
		}
	}
}

func TestValidateRejectsBadRules(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{"missing rule_id", Rule{Name: "x", Language: "java", Severity: "high", Description: "d", Remediation: "r", Detection: Detection{Kind: DetectionASTCall, Patterns: []CallPattern{{Callee: "x"}}}, Confidence: ConfidenceModel{Base: 0.5}}},
		{"bad severity", Rule{RuleID: "SC-X-001", Name: "x", Language: "java", Severity: "omg", Description: "d", Remediation: "r", Detection: Detection{Kind: DetectionASTCall, Patterns: []CallPattern{{Callee: "x"}}}, Confidence: ConfidenceModel{Base: 0.5}}},
		{"confidence > 1", Rule{RuleID: "SC-X-001", Name: "x", Language: "java", Severity: "high", Description: "d", Remediation: "r", Detection: Detection{Kind: DetectionASTCall, Patterns: []CallPattern{{Callee: "x"}}}, Confidence: ConfidenceModel{Base: 1.5}}},
		{"empty pattern", Rule{RuleID: "SC-X-001", Name: "x", Language: "java", Severity: "high", Description: "d", Remediation: "r", Detection: Detection{Kind: DetectionASTCall, Patterns: []CallPattern{{}}}, Confidence: ConfidenceModel{Base: 0.5}}},
		{"bad regex", Rule{RuleID: "SC-X-001", Name: "x", Language: "java", Severity: "high", Description: "d", Remediation: "r", Detection: Detection{Kind: DetectionASTCall, Patterns: []CallPattern{{Callee: "x", ArgMatchesAny: []string{"(unclosed"}}}}, Confidence: ConfidenceModel{Base: 0.5}}},
		{"unsupported kind", Rule{RuleID: "SC-X-001", Name: "x", Language: "java", Severity: "high", Description: "d", Remediation: "r", Detection: Detection{Kind: "taint"}, Confidence: ConfidenceModel{Base: 0.5}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(&tc.rule); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}
