package audit

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestAction_Domain(t *testing.T) {
	cases := map[Action]string{
		AuthLoginSucceeded:  "auth",
		RiskResolved:        "risk",
		GovernanceSLAViolated: "governance",
		APIKeyUsed:          "apikey",
		Action("bare"):      "bare",
		Action(""):          "",
	}
	for a, want := range cases {
		if got := a.Domain(); got != want {
			t.Errorf("%q.Domain() = %q, want %q", a, got, want)
		}
	}
}

func TestAllActions_ShapedCorrectly(t *testing.T) {
	// Every action: lowercase, dot-separated, ≥2 segments, past-tense-ish.
	pattern := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$`)
	for _, a := range AllActions() {
		if !pattern.MatchString(string(a)) {
			t.Errorf("action %q does not match required shape", a)
		}
	}
}

func TestAllActions_NoDuplicates(t *testing.T) {
	seen := map[Action]bool{}
	for _, a := range AllActions() {
		if seen[a] {
			t.Errorf("duplicate action: %q", a)
		}
		seen[a] = true
	}
}

// TestActionTaxonomyDriftCheck fails if the set of constants in actions.go
// does not match the set of action codes documented in
// docs/audit-action-taxonomy.md. Adds + removals MUST land in both places.
//
// Runs only when the taxonomy doc exists — this is a guard, not a block.
func TestActionTaxonomyDriftCheck(t *testing.T) {
	const docPath = "../../docs/audit-action-taxonomy.md"
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Skipf("taxonomy doc %s not yet created: %v", docPath, err)
	}
	// Action codes appear as the first cell of a table row, i.e. as
	// `| \`<code>\` |`. This excludes file paths / table names that also
	// use dot-notation but live in prose or later cells.
	actionRE := regexp.MustCompile("\\|\\s*`([a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*){1,3})`\\s*\\|")
	matches := actionRE.FindAllStringSubmatch(string(raw), -1)
	inDoc := map[string]bool{}
	for _, m := range matches {
		inDoc[m[1]] = true
	}

	inCode := map[string]bool{}
	for _, a := range AllActions() {
		inCode[string(a)] = true
	}

	var missingFromDoc, missingFromCode []string
	for k := range inCode {
		if !inDoc[k] {
			missingFromDoc = append(missingFromDoc, k)
		}
	}
	for k := range inDoc {
		if !inCode[k] {
			missingFromCode = append(missingFromCode, k)
		}
	}
	sort.Strings(missingFromDoc)
	sort.Strings(missingFromCode)
	if len(missingFromDoc) > 0 {
		t.Errorf("actions in code but not in %s:\n  %s",
			docPath, strings.Join(missingFromDoc, "\n  "))
	}
	if len(missingFromCode) > 0 {
		t.Errorf("actions in %s but not in code:\n  %s",
			docPath, strings.Join(missingFromCode, "\n  "))
	}
}
