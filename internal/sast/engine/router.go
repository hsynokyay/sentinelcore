// Package engine — router.go owns rule→module routing.
//
// Before this file existed, the rule→module match was an inline check
// inside Engine.Analyze that only consulted the legacy single Language
// field. v2 rules that set the plural Languages array (and left singular
// Language empty) slipped past the engine's filter and ran against
// modules of every language — exactly the cross-language false-positive
// class that Sprint 1.1 of SENTINELCORE_ROADMAP.md was opened to fix.
//
// The complementary "file extension → canonical language name" map lives
// in `internal/sast/lang` so that the per-language frontend walkers can
// depend on it without creating a frontend→engine cycle.

package engine

import (
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

// RuleMatchesModule reports whether the given compiled rule should be
// evaluated against the given IR module. The contract:
//
//   - If the rule declares no Languages and no legacy Language, it is a
//     wildcard rule and matches every module. This preserves backward
//     compatibility with rules predating the field; Sprint 1.3 will
//     promote "Languages required" via Validate.
//
//   - Otherwise the rule matches when `module.Language` is contained in
//     the rule's effective language set. The effective set is
//     `rule.Source.Languages` after MigrateInPlace, which guarantees the
//     legacy singular `Language` has already been promoted into the
//     plural `Languages` slice. We still honor a non-empty singular
//     `Language` as a fallback in case a caller hands the engine a rule
//     that bypassed the loader's MigrateInPlace pass (only really
//     happens in unit tests).
func RuleMatchesModule(rule *rules.CompiledRule, module *ir.Module) bool {
	if rule == nil || rule.Source == nil || module == nil {
		return false
	}
	src := rule.Source
	if len(src.Languages) == 0 && src.Language == "" {
		return true
	}
	if module.Language == "" {
		// A module with no detected language can't match a language-scoped
		// rule. This is an unusual case (every parser sets Module.Language)
		// but worth defending against — better a missed finding on a
		// malformed module than a false positive across the whole rule set.
		return false
	}
	for _, lang := range src.Languages {
		if lang == module.Language {
			return true
		}
	}
	// Last-resort fallback for un-migrated rules. Engine code paths always
	// go through the loader so this is dead in production, but keeps
	// engine tests that hand-build a Rule from succeeding even if they
	// forget to call MigrateInPlace.
	return src.Language != "" && src.Language == module.Language
}
