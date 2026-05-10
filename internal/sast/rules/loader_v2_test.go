package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------- migration ----------

func TestMigrateInPlace_PromotesV1ToV2(t *testing.T) {
	r := &Rule{
		RuleID:   "SC-JAVA-DESER-001",
		Name:     "x",
		Language: "java",
	}
	MigrateInPlace(r)
	if r.SchemaVersion != 2 {
		t.Errorf("schema_version: got %d, want 2", r.SchemaVersion)
	}
	if got := r.Languages; len(got) != 1 || got[0] != "java" {
		t.Errorf("languages: got %v, want [java]", got)
	}
	if r.Category != "deserialization" {
		t.Errorf("category: got %q, want deserialization (inferred from rule_id token DESER)", r.Category)
	}
}

func TestMigrateInPlace_NormalizesLanguageAliases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"js", "javascript"},
		{"ts", "javascript"},
		{"typescript", "javascript"},
		{"py", "python"},
		{"cs", "csharp"},
		{"java", "java"},               // canonical, untouched
		{"javascript", "javascript"},  // canonical, untouched
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			r := &Rule{RuleID: "SC-X-CAT-001", Name: "x", Language: tc.in}
			MigrateInPlace(r)
			if r.Language != tc.want {
				t.Errorf("Language: got %q, want %q", r.Language, tc.want)
			}
			if len(r.Languages) == 0 || r.Languages[0] != tc.want {
				t.Errorf("Languages[0]: got %v, want [%s]", r.Languages, tc.want)
			}
		})
	}
}

func TestMigrateInPlace_IsIdempotent(t *testing.T) {
	r := &Rule{
		SchemaVersion: 2,
		RuleID:        "SC-PY-DESER-001",
		Languages:     []string{"python"},
		Category:      "deserialization",
	}
	// Snapshot AFTER the first migration: subsequent migrations must be
	// no-ops on the already-promoted form. Snapshotting BEFORE would
	// conflate "MigrateInPlace fills missing fields" (expected — that's
	// the whole point) with "running it again changes something" (the
	// actual idempotency claim).
	MigrateInPlace(r)
	snapshot, _ := json.Marshal(r)
	MigrateInPlace(r)
	again, _ := json.Marshal(r)
	if string(snapshot) != string(again) {
		t.Errorf("migration not idempotent\nafter 1st: %s\nafter 2nd: %s", snapshot, again)
	}
}

func TestInferCategoryFromRuleID(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"SC-JAVA-DESER-001", "deserialization"},
		{"SC-PY-DESER-PICKLE-001", "deserialization"},
		{"SC-JS-XSS-001", "xss"},
		{"SC-CSHARP-SQL-001", "injection"},
		{"SC-CSHARP-CMD-001", "injection"},
		{"SC-JS-PROTO-POL-001", "injection"},
		{"SC-JAVA-XXE-001", "xxe"},
		{"SC-JS-CRYPTO-001", "crypto"},
		{"SC-PY-SECRET-001", "secret"},
		{"SC-JAVA-LOG-001", "logging"},
		{"SC-JS-REDIRECT-001", "redirect"},
		{"SC-PY-SSRF-002", "ssrf"},
		{"SC-XX-NOT-A-CATEGORY-999", "misc"}, // unknown → misc, not error
		{"BAD", "misc"},                       // malformed → misc
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if got := inferCategoryFromRuleID(tc.id); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------- v2 validation ----------

func TestValidate_RejectsUnknownCategory(t *testing.T) {
	r := minimalASTCallRule()
	r.Category = "made-up-category"
	if err := Validate(r); err == nil {
		t.Fatal("expected error for unknown category")
	}
}

func TestValidate_AcceptsTaintV2Shape(t *testing.T) {
	r := minimalASTCallRule()
	idx := 0
	r.Detection = Detection{
		Kind: DetectionTaint,
		Taint: &TaintSpec{
			Sources: []TaintNode{
				{Kind: TaintKindAPI, FQN: []string{"flask.request.args.get"}},
			},
			Sinks: []TaintNode{
				{Kind: TaintKindAPI, FQN: []string{"jinja2.Template.render"}, ArgumentIndex: &idx},
			},
		},
	}
	if err := Validate(r); err != nil {
		t.Fatalf("v2 taint should validate, got: %v", err)
	}
}

func TestValidate_TaintRequiresSourcesAndSinks(t *testing.T) {
	r := minimalASTCallRule()
	r.Detection = Detection{
		Kind:  DetectionTaint,
		Taint: &TaintSpec{Sources: []TaintNode{{Kind: TaintKindAPI, FQN: []string{"x"}}}},
	}
	if err := Validate(r); err == nil || !strings.Contains(err.Error(), "sinks") {
		t.Errorf("expected 'sinks required' error, got: %v", err)
	}
}

func TestValidate_TaintAllNodeKinds(t *testing.T) {
	cases := []struct {
		name string
		node TaintNode
		want string // empty if should pass; substring of error message otherwise
	}{
		{"api_ok", TaintNode{Kind: TaintKindAPI, FQN: []string{"x.y"}}, ""},
		{"api_missing_fqn", TaintNode{Kind: TaintKindAPI}, "fqn"},
		{"framework_param_ok", TaintNode{Kind: TaintKindFrameworkParam, Framework: "spring_mvc", Annotations: []string{"@RequestParam"}}, ""},
		{"framework_param_missing_apis", TaintNode{Kind: TaintKindFrameworkParam, Framework: "flask"}, "annotations or apis"},
		{"type_cast_ok", TaintNode{Kind: TaintKindTypeCast, ToTypes: []string{"int"}}, ""},
		{"type_cast_missing", TaintNode{Kind: TaintKindTypeCast}, "to_types"},
		{"regex_check_ok", TaintNode{Kind: TaintKindRegexCheck, Pattern: "^[a-z]+$"}, ""},
		{"regex_check_invalid", TaintNode{Kind: TaintKindRegexCheck, Pattern: "[unclosed"}, "regex_check pattern"},
		{"format_ok", TaintNode{Kind: TaintKindFormat, Operations: []string{"fstring"}}, ""},
		{"format_missing", TaintNode{Kind: TaintKindFormat}, "operations"},
		{"unknown_kind", TaintNode{Kind: "wat"}, "is not supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTaintNode(tc.node)
			if tc.want == "" {
				if err != nil {
					t.Errorf("expected pass, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error containing %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestValidate_ConfidenceModifiers(t *testing.T) {
	r := minimalASTCallRule()
	r.Confidence.Modifiers = []ConfidenceModifier{
		{If: "sanitizer_present", Delta: -0.4},
		{If: "source_is_user_input", Delta: 0.1},
	}
	if err := Validate(r); err != nil {
		t.Errorf("valid modifiers should pass, got: %v", err)
	}
}

func TestValidate_ConfidenceModifierRequiresIfAndDeltaRange(t *testing.T) {
	for _, tc := range []struct {
		name string
		mods []ConfidenceModifier
		want string
	}{
		{"missing_if", []ConfidenceModifier{{If: "", Delta: 0.1}}, "'if' is required"},
		{"delta_too_high", []ConfidenceModifier{{If: "x", Delta: 1.5}}, "delta must be in"},
		{"delta_too_low", []ConfidenceModifier{{If: "x", Delta: -2}}, "delta must be in"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := minimalASTCallRule()
			r.Confidence.Modifiers = tc.mods
			err := Validate(r)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error containing %q, got: %v", tc.want, err)
			}
		})
	}
}

// ---------- helpers ----------

func minimalASTCallRule() *Rule {
	return &Rule{
		SchemaVersion: 2,
		RuleID:        "SC-JAVA-CRYPTO-001",
		Name:          "x",
		Languages:     []string{"java"},
		Severity:      "high",
		Description:   "x",
		Remediation:   "x",
		Detection: Detection{
			Kind:     DetectionASTCall,
			Patterns: []CallPattern{{ReceiverFQN: "java.security.MessageDigest", Callee: "getInstance"}},
		},
		Confidence: ConfidenceModel{Base: 0.8},
	}
}

// ---------- builtins coverage ----------

// TestBuiltinsAllHaveCategoryAfterMigration is the load-time guard the
// validator CLI uses in CI: every shipped rule, after migration, must end
// up with a known Category. New rules added without an inferable token in
// the rule_id will surface here.
func TestBuiltinsAllHaveCategoryAfterMigration(t *testing.T) {
	rs, err := LoadBuiltins()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	miscOK := map[string]bool{} // intentionally allow nothing here for now
	for _, r := range rs {
		if r.Category == "misc" && !miscOK[r.RuleID] {
			t.Errorf("%s migrated to category=misc — add a token to inferCategoryFromRuleID or set Category explicitly in the JSON", r.RuleID)
		}
		if r.SchemaVersion != 2 {
			t.Errorf("%s: schema_version after migration = %d, want 2", r.RuleID, r.SchemaVersion)
		}
	}
}
