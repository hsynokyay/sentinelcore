package engine

import (
	"reflect"
	"sort"
	"strconv"
	"testing"
)

// f is a tiny helper that builds a Finding with just the fields the
// dedup pass cares about, leaving everything else zero. Avoids 12-line
// struct literals in every test case.
func f(rule, mod string, line int, vc, sev string) Finding {
	return Finding{
		RuleID:      rule,
		ModulePath:  mod,
		Line:        line,
		VulnClass:   vc,
		Severity:    sev,
		Fingerprint: rule + ":" + mod + ":" + strconv.Itoa(line),
	}
}

func ruleIDs(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, x := range fs {
		out[i] = x.RuleID
	}
	return out
}

func TestDedup_SameVulnClassDifferentRules(t *testing.T) {
	in := []Finding{
		f("SC-JAVA-SECRET-001", "Secrets.java", 27, "hardcoded_secret", "high"),
		f("SC-JAVA-JWT-003", "Secrets.java", 27, "hardcoded_secret", "high"),
	}
	out, rep := Deduplicate(in)

	if len(out) != 1 {
		t.Fatalf("expected 1 surviving finding, got %d (%v)", len(out), ruleIDs(out))
	}
	if rep.Suppressed != 1 {
		t.Errorf("expected Suppressed=1, got %d", rep.Suppressed)
	}
	if len(rep.Audit) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(rep.Audit))
	}
	a := rep.Audit[0]
	if a.ModulePath != "Secrets.java" || a.Line != 27 || a.VulnClass != "hardcoded_secret" {
		t.Errorf("audit entry mislabeled: %+v", a)
	}
	// The two surviving/suppressed identities must together account for
	// both inputs — but which one survived is a tie-break detail, not
	// a contract (per Sprint 1.2 design note).
	all := append([]string{a.KeptRuleID}, a.SuppressedRuleIDs...)
	sort.Strings(all)
	if !reflect.DeepEqual(all, []string{"SC-JAVA-JWT-003", "SC-JAVA-SECRET-001"}) {
		t.Errorf("audit identities mismatch: %v", all)
	}
}

func TestDedup_TieBreakIsDeterministic(t *testing.T) {
	// The actual winner of a severity tie isn't part of the contract,
	// but the result must be reproducible — running the same input
	// twice has to yield the same surviving rule_id, otherwise audit
	// logs and snapshot tests churn between runs.
	in := []Finding{
		f("SC-JAVA-SECRET-001", "Secrets.java", 27, "hardcoded_secret", "high"),
		f("SC-JAVA-JWT-003", "Secrets.java", 27, "hardcoded_secret", "high"),
	}
	out1, _ := Deduplicate(append([]Finding{}, in...))
	out2, _ := Deduplicate(append([]Finding{}, in...))
	if out1[0].RuleID != out2[0].RuleID {
		t.Errorf("dedup not deterministic: run1=%s run2=%s", out1[0].RuleID, out2[0].RuleID)
	}
	// Reverse order shouldn't matter either.
	rev := []Finding{in[1], in[0]}
	out3, _ := Deduplicate(rev)
	if out3[0].RuleID != out1[0].RuleID {
		t.Errorf("dedup result depends on input order: forward=%s reverse=%s",
			out1[0].RuleID, out3[0].RuleID)
	}
}

func TestDedup_SameVulnClassDifferentSeverity(t *testing.T) {
	in := []Finding{
		f("SC-JAVA-SECRET-001", "Foo.java", 10, "hardcoded_secret", "medium"),
		f("SC-JAVA-CRITSEC-001", "Foo.java", 10, "hardcoded_secret", "critical"),
		f("SC-JAVA-LOWSEC-001", "Foo.java", 10, "hardcoded_secret", "low"),
	}
	out, rep := Deduplicate(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].RuleID != "SC-JAVA-CRITSEC-001" {
		t.Errorf("expected critical-severity rule to win, got %s", out[0].RuleID)
	}
	if rep.Suppressed != 2 {
		t.Errorf("expected Suppressed=2, got %d", rep.Suppressed)
	}
}

func TestDedup_DifferentLines(t *testing.T) {
	in := []Finding{
		f("SC-JAVA-SECRET-001", "Foo.java", 10, "hardcoded_secret", "high"),
		f("SC-JAVA-SECRET-001", "Foo.java", 11, "hardcoded_secret", "high"),
	}
	out, rep := Deduplicate(in)
	if len(out) != 2 {
		t.Errorf("different-line findings must NOT dedup; got %d findings", len(out))
	}
	if rep.Suppressed != 0 {
		t.Errorf("expected Suppressed=0, got %d", rep.Suppressed)
	}
}

func TestDedup_DifferentVulnClass(t *testing.T) {
	// SQL injection and XSS legitimately co-occur on a single line
	// (e.g. an unsanitized HTTP parameter that flows into both a SQL
	// query and an HTML response). Both findings are real; collapse
	// would hide one bug.
	in := []Finding{
		f("SC-JAVA-SQL-001", "Foo.java", 50, "sql_injection", "critical"),
		f("SC-JAVA-XSS-001", "Foo.java", 50, "xss", "high"),
	}
	out, rep := Deduplicate(in)
	if len(out) != 2 {
		t.Errorf("different-vuln_class findings must NOT dedup; got %d", len(out))
	}
	if rep.Suppressed != 0 {
		t.Errorf("expected Suppressed=0, got %d", rep.Suppressed)
	}
}

func TestDedup_DifferentModule(t *testing.T) {
	in := []Finding{
		f("SC-JAVA-SECRET-001", "A.java", 10, "hardcoded_secret", "high"),
		f("SC-JAVA-SECRET-001", "B.java", 10, "hardcoded_secret", "high"),
	}
	out, _ := Deduplicate(in)
	if len(out) != 2 {
		t.Errorf("different-module findings must NOT dedup; got %d", len(out))
	}
}

func TestDedup_PreservesAuditTrail(t *testing.T) {
	in := []Finding{
		f("SC-JAVA-SECRET-001", "Foo.java", 10, "hardcoded_secret", "high"),
		f("SC-JAVA-JWT-003", "Foo.java", 10, "hardcoded_secret", "high"),
		f("SC-JAVA-AWS-001", "Foo.java", 10, "hardcoded_secret", "high"),
	}
	_, rep := Deduplicate(in)
	if len(rep.Audit) != 1 {
		t.Fatalf("expected 1 audit group, got %d", len(rep.Audit))
	}
	a := rep.Audit[0]
	if len(a.SuppressedRuleIDs) != 2 {
		t.Errorf("expected 2 suppressed rule_ids, got %d (%v)",
			len(a.SuppressedRuleIDs), a.SuppressedRuleIDs)
	}
}

func TestDedup_EmptyVulnClassDoesNotCollapse(t *testing.T) {
	// Two findings with no VulnClass at the same location must NOT
	// dedup against each other — empty class means "unknown", and
	// silently grouping unknowns would collapse semantically distinct
	// findings. Builtin rules should never produce this case after
	// MigrateInPlace; the guard is for hand-built/external findings.
	in := []Finding{
		f("EXT-CUSTOM-001", "Foo.java", 10, "", "high"),
		f("EXT-CUSTOM-002", "Foo.java", 10, "", "high"),
	}
	out, rep := Deduplicate(in)
	if len(out) != 2 {
		t.Errorf("empty-VulnClass findings must NOT collapse; got %d", len(out))
	}
	if rep.Suppressed != 0 {
		t.Errorf("expected Suppressed=0 for empty-VulnClass inputs, got %d", rep.Suppressed)
	}
}

func TestDedup_EmptyInput(t *testing.T) {
	out, rep := Deduplicate(nil)
	if out != nil {
		t.Errorf("nil input should pass through nil output; got %v", out)
	}
	if rep.Suppressed != 0 {
		t.Errorf("nil input must have Suppressed=0, got %d", rep.Suppressed)
	}
}

func TestDedup_PreservesInputOrder(t *testing.T) {
	in := []Finding{
		f("SC-JAVA-SQL-001", "A.java", 10, "sql_injection", "critical"),
		f("SC-JAVA-SECRET-001", "A.java", 20, "hardcoded_secret", "high"),
		f("SC-JAVA-XSS-001", "B.java", 5, "xss", "high"),
	}
	out, _ := Deduplicate(in)
	got := ruleIDs(out)
	want := []string{"SC-JAVA-SQL-001", "SC-JAVA-SECRET-001", "SC-JAVA-XSS-001"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order changed; got %v want %v", got, want)
	}
}
