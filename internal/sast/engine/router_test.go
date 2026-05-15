package engine

import (
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

// Note: the extension→language map and its tests live in
// `internal/sast/lang` so per-language frontend walkers can depend on it
// without creating an import cycle.

// newRule builds a minimal CompiledRule wrapping a Rule with the given
// language fields. We don't go through Compile() because the routing logic
// only consults rule.Source.{Language,Languages} — the compiled patterns
// are irrelevant here.
func newRule(language string, languages ...string) *rules.CompiledRule {
	return &rules.CompiledRule{
		Source: &rules.Rule{
			RuleID:    "SC-TEST-001",
			Language:  language,
			Languages: languages,
		},
	}
}

func TestRuleMatchesModule_Languages(t *testing.T) {
	javaMod := &ir.Module{Language: "java"}
	pyMod := &ir.Module{Language: "python"}

	javaRule := newRule("", "java")
	multiRule := newRule("", "java", "python")

	if !RuleMatchesModule(javaRule, javaMod) {
		t.Error("java-scoped rule should match java module")
	}
	if RuleMatchesModule(javaRule, pyMod) {
		t.Error("java-scoped rule should NOT match python module — this is the Sprint 1.1 bug")
	}
	if !RuleMatchesModule(multiRule, javaMod) {
		t.Error("[java,python] rule should match java module")
	}
	if !RuleMatchesModule(multiRule, pyMod) {
		t.Error("[java,python] rule should match python module")
	}
}

func TestRuleMatchesModule_LegacyLanguageOnly(t *testing.T) {
	// Edge case: caller hand-built a Rule with only the singular Language
	// field set and bypassed MigrateInPlace (e.g. a unit test). The engine
	// must still route correctly.
	javaMod := &ir.Module{Language: "java"}
	pyMod := &ir.Module{Language: "python"}

	rule := newRule("java")

	if !RuleMatchesModule(rule, javaMod) {
		t.Error("legacy single-language java rule should match java module")
	}
	if RuleMatchesModule(rule, pyMod) {
		t.Error("legacy single-language java rule should NOT match python module")
	}
}

func TestRuleMatchesModule_EmptyLanguages(t *testing.T) {
	// Wildcard rule (no language declared) matches every module. Required
	// for backward compatibility with pre-v2 rules; Sprint 1.3 will
	// promote "Languages required" via Validate.
	javaMod := &ir.Module{Language: "java"}
	pyMod := &ir.Module{Language: "python"}
	emptyMod := &ir.Module{Language: ""}

	wildcard := &rules.CompiledRule{Source: &rules.Rule{RuleID: "SC-WILD-001"}}

	if !RuleMatchesModule(wildcard, javaMod) {
		t.Error("wildcard rule should match java module")
	}
	if !RuleMatchesModule(wildcard, pyMod) {
		t.Error("wildcard rule should match python module")
	}
	if !RuleMatchesModule(wildcard, emptyMod) {
		t.Error("wildcard rule should match a module with no detected language")
	}
}

func TestRuleMatchesModule_LanguageScopedAgainstUnknownModule(t *testing.T) {
	// A module with empty Language can't satisfy a language-scoped rule —
	// returning true would be a regression of the Sprint 1.1 bug for any
	// future code path that produces a Module without setting Language.
	rule := newRule("", "java")
	mod := &ir.Module{Language: ""}
	if RuleMatchesModule(rule, mod) {
		t.Error("language-scoped rule should NOT match a module with empty Language")
	}
}

func TestRuleMatchesModule_NilSafety(t *testing.T) {
	if RuleMatchesModule(nil, &ir.Module{Language: "java"}) {
		t.Error("nil rule must not match")
	}
	if RuleMatchesModule(newRule("", "java"), nil) {
		t.Error("nil module must not match")
	}
	if RuleMatchesModule(&rules.CompiledRule{Source: nil}, &ir.Module{Language: "java"}) {
		t.Error("rule with nil Source must not match")
	}
}
