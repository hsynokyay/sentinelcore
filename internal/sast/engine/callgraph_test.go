package engine

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

// TestBuildCallGraph_OverloadCollision_KeepsFirstDeclared verifies the
// observability contract added in AUDIT-2026-05-11 (P0-4): when two
// methods share the same FQN (overloads — SentinelIR Function.FQN does
// not yet encode parameter-type mangling), BuildCallGraph keeps the
// first-declared method, drops the second, and emits one counter
// increment on observability.SASTCallgraphOverloadCollisions.
//
// Sprint 4 frontend chunk will introduce full FQN parameter-type
// mangling; at that point both overloads will become distinct graph
// nodes, this test will fail at the "first-declared retention" assert,
// and the test will need updating. That is the correct failure mode —
// the test failing announces that the collision is no longer present.
func TestBuildCallGraph_OverloadCollision_KeepsFirstDeclared(t *testing.T) {
	counter := observability.SASTCallgraphOverloadCollisions.WithLabelValues("java")
	before := testutil.ToFloat64(counter)

	// Two methods with the same FQN, different parameter types.
	// Parameter.Value of 1 matches the ValueID the builder assigns to the
	// first parameter; tests don't drive a real analysis, so this is
	// nominal — only the FQN collision matters for this test.
	mod := ir.NewModule("test.java", "java").
		Class("Foo", "com.example.Foo").
		Method("findById", ir.Nominal("com.example.User"),
			ir.Parameter{Name: "id", Type: ir.Primitive("long"), Value: 1}).
		Done().
		Method("findById", ir.Nominal("com.example.User"),
			ir.Parameter{Name: "id", Type: ir.Nominal("java.lang.String"), Value: 1}).
		Done().
		Done().
		Build()

	cg := BuildCallGraph([]*ir.Module{mod})

	after := testutil.ToFloat64(counter)

	// Counter delta — exactly one collision observed for this module.
	if delta := after - before; delta != 1 {
		t.Errorf("SASTCallgraphOverloadCollisions{language=\"java\"} delta: got %v, want 1", delta)
	}

	// First-declared retention — the long-typed overload (declared first)
	// must be the one kept; the String-typed overload (declared second)
	// must be dropped.
	resolved := cg.Resolve("com.example.Foo.findById")
	if resolved == nil {
		t.Fatal("expected com.example.Foo.findById to resolve after collision, got nil")
	}
	if len(resolved.Function.Parameters) != 1 {
		t.Fatalf("expected 1 parameter on resolved method, got %d", len(resolved.Function.Parameters))
	}
	if got := resolved.Function.Parameters[0].Type.Name; got != "long" {
		t.Errorf("first-declared overload should be kept (param type long); got %q — second overload won", got)
	}
}

// TestBuildCallGraph_NoCollision_NoCounterChange is the negative-case
// sibling: when methods have distinct FQNs, no counter increment fires.
// Guards against an accidental "always increment" regression on the
// hot path.
func TestBuildCallGraph_NoCollision_NoCounterChange(t *testing.T) {
	counter := observability.SASTCallgraphOverloadCollisions.WithLabelValues("java")
	before := testutil.ToFloat64(counter)

	mod := ir.NewModule("test2.java", "java").
		Class("Foo", "com.example.Foo2").
		Method("findById", ir.Nominal("com.example.User"),
			ir.Parameter{Name: "id", Type: ir.Primitive("long"), Value: 1}).
		Done().
		Method("findByName", ir.Nominal("com.example.User"),
			ir.Parameter{Name: "name", Type: ir.Nominal("java.lang.String"), Value: 1}).
		Done().
		Done().
		Build()

	cg := BuildCallGraph([]*ir.Module{mod})

	after := testutil.ToFloat64(counter)
	if delta := after - before; delta != 0 {
		t.Errorf("SASTCallgraphOverloadCollisions{language=\"java\"} delta: got %v, want 0 (distinct FQNs must not collide)", delta)
	}

	// Both methods must be resolvable.
	if cg.Resolve("com.example.Foo2.findById") == nil {
		t.Error("expected com.example.Foo2.findById to resolve")
	}
	if cg.Resolve("com.example.Foo2.findByName") == nil {
		t.Error("expected com.example.Foo2.findByName to resolve")
	}
}
