package engine

import (
	"fmt"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

// Engine is the top-level SAST analysis orchestrator. It owns the compiled
// rule set, the taint model set, and exposes Analyze(module) → []Finding
// for the worker to call per parsed module.
//
// The engine is stateless between calls: each Analyze() walks the supplied
// module independently, which means a worker can call Analyze concurrently
// from multiple goroutines on different modules without locking.
type Engine struct {
	rules  []*rules.CompiledRule
	taint  *TaintEngine
	models *ModelSet
}

// New creates an Engine from a pre-compiled rule set and a model set.
func New(compiled []*rules.CompiledRule, models *ModelSet) *Engine {
	var te *TaintEngine
	if models != nil {
		te = NewTaintEngine(models)
	}
	return &Engine{rules: compiled, taint: te, models: models}
}

// NewFromBuiltins loads and compiles the embedded built-in rules and models.
// Intended for tests and the default worker configuration.
func NewFromBuiltins() (*Engine, error) {
	raw, err := rules.LoadBuiltins()
	if err != nil {
		return nil, fmt.Errorf("load builtins: %w", err)
	}
	compiled, err := rules.CompileAll(raw)
	if err != nil {
		return nil, fmt.Errorf("compile builtins: %w", err)
	}
	models, err := LoadBuiltinModels()
	if err != nil {
		return nil, fmt.Errorf("load models: %w", err)
	}
	return New(compiled, models), nil
}

// Analyze runs every compatible rule against the supplied module and
// returns all findings. The order of returned findings is stable per-module
// (classes × methods × blocks × instructions × rules × patterns) so
// snapshot-style tests produce reproducible output.
func (e *Engine) Analyze(module *ir.Module) []Finding {
	var out []Finding
	for _, rule := range e.rules {
		// Language filter — rules only apply to their declared language(s).
		// Delegated to RuleMatchesModule so the v2 plural Languages array
		// is honored alongside the legacy singular Language. Without this
		// 36 of the 99 builtin rules (which only set Languages, not
		// Language) ran against modules of every language and produced
		// cross-language false positives — the bug Sprint 1.1 fixes.
		if !RuleMatchesModule(rule, module) {
			continue
		}
		switch rule.Source.Detection.Kind {
		case rules.DetectionASTCall:
			out = append(out, matchASTCallRule(module, rule)...)
		case rules.DetectionASTAssign:
			out = append(out, matchASTAssignRule(module, rule)...)
		case rules.DetectionTaint:
			if e.taint != nil {
				for _, cls := range module.Classes {
					for _, fn := range cls.Methods {
						out = append(out, e.taint.AnalyzeFunction(module, fn, rule)...)
					}
				}
			}
		}
	}
	return out
}

// AnalyzeAll runs analysis across every supplied module with
// inter-procedural support and returns the deduplicated finding set.
// Two layers of dedup run in sequence:
//
//  1. Fingerprint dedup (existing): collapses identical re-runs of the
//     same rule, e.g. inter-procedural pre-pass + main pass producing
//     the byte-identical Finding twice.
//  2. Semantic dedup (Sprint 1.2): collapses different rules that
//     classify the same vulnerability at the same source location —
//     see dedup.go.
//
// Callers that need the dedup audit report (suppressed count, which
// rule_ids superseded which) should use AnalyzeAllWithReport instead.
func (e *Engine) AnalyzeAll(modules []*ir.Module) []Finding {
	out, _ := e.AnalyzeAllWithReport(modules)
	return out
}

// AnalyzeAllWithReport is identical to AnalyzeAll but also returns the
// dedup audit report. Worker code persists the report's Suppressed
// count into scan-job metadata as `findings_deduplicated` and emits
// the per-group Audit entries to the structured operator log.
func (e *Engine) AnalyzeAllWithReport(modules []*ir.Module) ([]Finding, DedupReport) {
	// Build call graph and wire into the taint engine for inter-proc.
	if e.taint != nil {
		cg := BuildCallGraph(modules)
		e.taint.SetCallGraph(cg)

		// Pre-pass: analyze every function twice to populate summaries.
		// Pass 1 builds leaf-function summaries (functions that don't call
		// other user-defined functions). Pass 2 uses those summaries when
		// analyzing caller functions. This two-iteration approach handles
		// single-level call chains correctly; deeper chains (A→B→C) would
		// need a topological sort.
		for pass := 0; pass < 2; pass++ {
			for _, rule := range e.rules {
				if rule.Source.Detection.Kind != rules.DetectionTaint {
					continue
				}
				for _, mod := range modules {
					if !RuleMatchesModule(rule, mod) {
						continue
					}
					for _, cls := range mod.Classes {
						for _, fn := range cls.Methods {
							_ = e.taint.AnalyzeFunction(mod, fn, rule)
						}
					}
				}
			}
		}
	}

	// Main analysis pass — fingerprint dedup along the way.
	var fingerprinted []Finding
	seen := map[string]bool{}
	for _, m := range modules {
		for _, f := range e.Analyze(m) {
			if !seen[f.Fingerprint] {
				seen[f.Fingerprint] = true
				fingerprinted = append(fingerprinted, f)
			}
		}
	}

	// Semantic dedup pass: collapse different rules that tagged the
	// same (file, line, vuln_class). The fingerprint pass above can't
	// see these because the rule_ids differ.
	return Deduplicate(fingerprinted)
}

// RuleCount returns the number of compiled rules loaded in this engine.
// Used by the worker's startup log line so operators can verify which rule
// version is running.
func (e *Engine) RuleCount() int {
	return len(e.rules)
}
