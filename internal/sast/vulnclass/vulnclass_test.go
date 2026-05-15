package vulnclass

import (
	"sort"
	"strings"
	"testing"
)

// TestRegistry_AllConstantsValid is the round-trip check: every
// constant declared in vulnclass.go must be in the validation set.
// Guards against an author adding a `const FooBar = "foo_bar"` line
// without remembering to add it to the `all` slice.
func TestRegistry_AllConstantsValid(t *testing.T) {
	declared := []VulnClass{
		SQLInjection, CommandInjection, LDAPInjection, XPathInjection,
		NoSQLInjection, ExpressionInjection, GenericInjection,
		TemplateInjection, UnsafeEval, PrototypePollution,
		XSS, PathTraversal, SSRF, OpenRedirect, XXE,
		WeakCrypto, InsecureTLS, InsecureRandom,
		HardcodedSecret, AuthBypass, AuthzBypass,
		AuthHeaderInjection, HTTPHeaderInjection,
		InsecureSession, InsecureCookie, MissingCSRF,
		UnsafeDeserialization,
		LogInjection, SensitiveLogging, PIIExposure,
		MassAssignment, InfoDisclosure, MemorySafety,
		NullDeref, RaceCondition, InputValidation,
	}
	for _, vc := range declared {
		if !IsValid(vc) {
			t.Errorf("constant %q is declared in vulnclass.go but not in the validation set; missing entry in all", vc)
		}
	}

	// Symmetric: All() length must match the declared count. If they
	// differ, either a constant is missing from all or all has a stray
	// entry not declared above.
	if len(All()) != len(declared) {
		t.Errorf("All() length %d != declared count %d — declaration drift", len(All()), len(declared))
	}
}

// TestRegistry_RejectsInvalid asserts the registry does not silently
// accept near-miss inputs. The classes of bad input it must reject:
//   - empty string
//   - uppercase / SCREAMING_SNAKE (the pre-Sprint-1.3 heuristic form)
//   - whitespace / case variations
//   - unknown class names
//   - inferred rule-id fallback like "RULE:SC-XYZ-001"
func TestRegistry_RejectsInvalid(t *testing.T) {
	rejects := []string{
		"",
		"SQL_INJECTION",   // uppercase — the legacy heuristic form
		"Sql_Injection",   // mixed case
		" sql_injection ", // surrounding whitespace
		"sqli",            // shorthand
		"foo_injection",   // unknown
		"RULE:SC-XYZ-001", // InferVulnClass fallback marker
	}
	for _, s := range rejects {
		if IsValidString(s) {
			t.Errorf("IsValidString(%q) returned true; the registry must reject this form", s)
		}
	}
}

// TestRegistry_AllValuesLowercaseSnake enforces the canonical-form
// invariant: every registry value must be lowercase snake_case. This
// is the contract that lets explicit JSON values and heuristic-derived
// values dedup against each other in engine.Deduplicate.
func TestRegistry_AllValuesLowercaseSnake(t *testing.T) {
	for _, vc := range All() {
		s := string(vc)
		if s == "" {
			t.Error("registry contains empty-string vuln_class")
			continue
		}
		if s != strings.ToLower(s) {
			t.Errorf("vuln_class %q is not lowercase — registry contract requires lowercase snake_case", s)
		}
		if strings.ContainsAny(s, " \t\n-") {
			t.Errorf("vuln_class %q contains whitespace or hyphen; use snake_case underscores", s)
		}
	}
}

// TestRegistry_NoDuplicates guards against an editor accidentally
// duplicating an entry in the all slice (e.g. cherry-pick conflict
// resolution gone wrong).
func TestRegistry_NoDuplicates(t *testing.T) {
	seen := make(map[VulnClass]int, len(All()))
	for i, vc := range All() {
		if prev, dup := seen[vc]; dup {
			t.Errorf("vuln_class %q appears twice (positions %d and %d)", vc, prev, i)
		}
		seen[vc] = i
	}
}

// TestScorecardOrder_AllValid — every scorecard-order entry must be a
// valid vuln_class. Curated subsets cannot drift away from canonical.
func TestScorecardOrder_AllValid(t *testing.T) {
	for _, vc := range ScorecardOrder() {
		if !IsValid(vc) {
			t.Errorf("ScorecardOrder() entry %q is not in the canonical registry", vc)
		}
	}
}

// TestAll_ReturnsCopy verifies callers cannot mutate the underlying
// canonical order via the returned slice. Sorting the result of All()
// must not change subsequent calls.
func TestAll_ReturnsCopy(t *testing.T) {
	first := All()
	sort.Slice(first, func(i, j int) bool { return first[i] > first[j] })

	second := All()
	if string(second[0]) != string(SQLInjection) {
		t.Errorf("All() shares state with caller — second call first element was %q, expected %q",
			second[0], SQLInjection)
	}
}
