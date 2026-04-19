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
		// Language filter — rules only apply to their declared language.
		if rule.Source.Language != "" && rule.Source.Language != module.Language {
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

// AnalyzeAll runs analysis across every supplied module with inter-procedural
// support. It builds a call graph, populates summaries in a bottom-up pass,
// and then runs the full analysis. Findings are deduplicated by fingerprint.
func (e *Engine) AnalyzeAll(modules []*ir.Module) []Finding {
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
					if rule.Source.Language != "" && rule.Source.Language != mod.Language {
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

	// Main analysis pass.
	var out []Finding
	seen := map[string]bool{}
	for _, m := range modules {
		for _, f := range e.Analyze(m) {
			if !seen[f.Fingerprint] {
				seen[f.Fingerprint] = true
				out = append(out, f)
			}
		}
	}
	return out
}

// RuleCount returns the number of compiled rules loaded in this engine.
// Used by the worker's startup log line so operators can verify which rule
// version is running.
func (e *Engine) RuleCount() int {
	return len(e.rules)
}
