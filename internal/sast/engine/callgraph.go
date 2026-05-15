package engine

import (
	"github.com/rs/zerolog/log"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

// CallGraph maps callee FQN → list of Functions across all modules in a
// scan. Used by the inter-procedural taint engine to resolve calls and
// retrieve function summaries.
//
// Chunk SAST-4 uses a simplified CHA-like approach: we index every function
// by its FQN, and when the taint engine encounters a Call instruction with
// a CalleeFQN, it looks it up here. Virtual dispatch refinement (looking at
// class hierarchy for overrides) is deferred to a later chunk — for the MVP,
// exact FQN match is sufficient because most enterprise Java code calls
// methods on concrete types (e.g. `dao.findById(...)` where `dao` is the
// concrete type declared at the call site).
type CallGraph struct {
	// funcs maps fully-qualified method name → function definition.
	// When multiple overloads exist (same FQN, different parameter
	// signatures), the first-declared method wins; subsequent overloads
	// are dropped from the graph. The drop is observed via the
	// observability.SASTCallgraphOverloadCollisions counter and a paired
	// Debug-level log entry recording which method displaced which.
	// Full FQN parameter-type mangling that eliminates the collision lands
	// with the Sprint 4 frontend chunk per AUDIT-2026-05-11, P0-4.
	funcs map[string]*FuncNode
}

// FuncNode bundles an ir.Function with the module it came from, for
// evidence-chain construction.
type FuncNode struct {
	Module   *ir.Module
	Class    *ir.Class
	Function *ir.Function
}

// BuildCallGraph indexes every function in every module by its FQN.
//
// Overload collisions (same FQN reseen with a different parameter
// signature) are inherent to the current SentinelIR Function.FQN format
// which does not encode parameter types. First-declared method wins;
// subsequent overloads are dropped and reported via
// observability.SASTCallgraphOverloadCollisions plus a Debug log. When
// the counter trends non-zero in production scans, prioritize the
// Sprint 4 frontend chunk that introduces full FQN parameter-type
// mangling (AUDIT-2026-05-11, P0-4).
func BuildCallGraph(modules []*ir.Module) *CallGraph {
	cg := &CallGraph{funcs: map[string]*FuncNode{}}
	for _, mod := range modules {
		for _, cls := range mod.Classes {
			for _, fn := range cls.Methods {
				if fn.FQN == "" {
					continue
				}
				if existing, exists := cg.funcs[fn.FQN]; exists {
					observability.SASTCallgraphOverloadCollisions.
						WithLabelValues(mod.Language).Inc()
					log.Debug().
						Str("fqn", fn.FQN).
						Str("kept_module", existing.Module.Path).
						Int("kept_line", existing.Function.Loc.Line).
						Str("dropped_module", mod.Path).
						Int("dropped_line", fn.Loc.Line).
						Str("language", mod.Language).
						Msg("sast callgraph overload collision; first-declared kept")
					continue
				}
				cg.funcs[fn.FQN] = &FuncNode{
					Module:   mod,
					Class:    cls,
					Function: fn,
				}
			}
		}
	}
	return cg
}

// Resolve returns the FuncNode for the given callee FQN, or nil if unresolved.
func (cg *CallGraph) Resolve(calleeFQN string) *FuncNode {
	return cg.funcs[calleeFQN]
}

// ResolveWithPackage tries exact FQN first, then prepends the module's
// package to handle same-package calls like `SqlHelper.runQuery` →
// `com.example.SqlHelper.runQuery`.
func (cg *CallGraph) ResolveWithPackage(calleeFQN, pkg string) *FuncNode {
	if fn := cg.funcs[calleeFQN]; fn != nil {
		return fn
	}
	if pkg != "" && calleeFQN != "" {
		qualified := pkg + "." + calleeFQN
		if fn := cg.funcs[qualified]; fn != nil {
			return fn
		}
	}
	return nil
}

// AllFunctions returns every indexed function. Used for bottom-up ordering.
func (cg *CallGraph) AllFunctions() []*FuncNode {
	out := make([]*FuncNode, 0, len(cg.funcs))
	for _, fn := range cg.funcs {
		out = append(out, fn)
	}
	return out
}
