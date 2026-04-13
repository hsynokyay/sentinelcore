package engine

import (
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
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
	// When multiple overloads exist (same FQN, different parameter counts),
	// we store the first one encountered — the taint engine treats this as
	// a "best effort" resolution. Full overload resolution lands with the
	// JVM sidecar frontend.
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
func BuildCallGraph(modules []*ir.Module) *CallGraph {
	cg := &CallGraph{funcs: map[string]*FuncNode{}}
	for _, mod := range modules {
		for _, cls := range mod.Classes {
			for _, fn := range cls.Methods {
				if fn.FQN != "" {
					cg.funcs[fn.FQN] = &FuncNode{
						Module:   mod,
						Class:    cls,
						Function: fn,
					}
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
