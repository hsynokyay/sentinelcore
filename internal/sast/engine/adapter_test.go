package engine

import (
	"strings"
	"testing"
)

func TestToMessageMapsSASTFinding(t *testing.T) {
	f := Finding{
		RuleID:      "SC-JAVA-SQL-001",
		Title:       "SQL Injection via Statement.executeQuery",
		Description: "User-controlled input...",
		CWE:         []string{"CWE-89"},
		OWASP:       []string{"A03:2021"},
		Severity:    "critical",
		Confidence:  0.90,
		ModulePath:  "src/main/java/Foo.java",
		Function:    "com.example.Foo.handle",
		Line:        17,
		Fingerprint: "abcd1234" + strings.Repeat("0", 56),
	}

	msg := ToMessage(f, "scan-123", "proj-456")

	if msg.ScanJobID != "scan-123" {
		t.Errorf("scan_job_id: %q", msg.ScanJobID)
	}
	if msg.ProjectID != "proj-456" {
		t.Errorf("project_id: %q", msg.ProjectID)
	}
	if msg.FindingType != "sast" {
		t.Errorf("finding_type: %q", msg.FindingType)
	}
	if msg.RuleID != "SC-JAVA-SQL-001" {
		t.Errorf("rule_id: %q", msg.RuleID)
	}
	if msg.CWEID != 89 {
		t.Errorf("cwe_id: %d", msg.CWEID)
	}
	if msg.Severity != "critical" {
		t.Errorf("severity: %q", msg.Severity)
	}
	if msg.Confidence != "high" {
		t.Errorf("confidence: got %q, want high (0.90 >= 0.75)", msg.Confidence)
	}
	if msg.FilePath != "src/main/java/Foo.java" {
		t.Errorf("file_path: %q", msg.FilePath)
	}
	if msg.LineStart != 17 {
		t.Errorf("line_start: %d", msg.LineStart)
	}
}

func TestToMessageSecretType(t *testing.T) {
	f := Finding{
		RuleID:     "SC-JAVA-SECRET-001",
		CWE:        []string{"CWE-798"},
		Severity:   "high",
		Confidence: 0.80,
	}
	msg := ToMessage(f, "", "")
	if msg.FindingType != "secret" {
		t.Errorf("secret rule should map to finding_type=secret, got %q", msg.FindingType)
	}
}

func TestConfidenceBucketing(t *testing.T) {
	cases := []struct {
		conf float64
		want string
	}{
		{0.95, "high"},
		{0.75, "high"},
		{0.74, "medium"},
		{0.40, "medium"},
		{0.39, "low"},
		{0.10, "low"},
	}
	for _, tc := range cases {
		f := Finding{Confidence: tc.conf, CWE: []string{"CWE-1"}, Severity: "info"}
		msg := ToMessage(f, "", "")
		if msg.Confidence != tc.want {
			t.Errorf("confidence %.2f → %q, want %q", tc.conf, msg.Confidence, tc.want)
		}
	}
}

func TestToTaintPathRows(t *testing.T) {
	f := Finding{
		Evidence: []EvidenceStep{
			{StepIndex: 0, ModulePath: "Foo.java", Line: 10, Function: "a.b.c", Description: "source: getParameter"},
			{StepIndex: 1, ModulePath: "Foo.java", Line: 12, Function: "a.b.c", Description: "propagation: concat"},
			{StepIndex: 2, ModulePath: "Foo.java", Line: 15, Function: "a.b.c", Description: "sink: executeQuery"},
		},
	}

	rows := ToTaintPathRows(f, "finding-uuid-1")
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	if rows[0].StepKind != "source" {
		t.Errorf("row[0] kind: %q", rows[0].StepKind)
	}
	if rows[1].StepKind != "propagation" {
		t.Errorf("row[1] kind: %q", rows[1].StepKind)
	}
	if rows[2].StepKind != "sink" {
		t.Errorf("row[2] kind: %q", rows[2].StepKind)
	}
	if rows[0].FindingID != "finding-uuid-1" {
		t.Errorf("finding_id: %q", rows[0].FindingID)
	}
}

func TestToTaintPathRowsSingleStep(t *testing.T) {
	f := Finding{
		Evidence: []EvidenceStep{
			{StepIndex: 0, ModulePath: "Foo.java", Line: 5, Description: "weak crypto"},
		},
	}
	rows := ToTaintPathRows(f, "f-1")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].StepKind != "source" {
		t.Errorf("single-step kind: %q, want source", rows[0].StepKind)
	}
}
