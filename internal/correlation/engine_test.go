package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	corr "github.com/sentinelcore/sentinelcore/pkg/correlation"
)

func TestEngine_ProcessScan_SASTOnly(t *testing.T) {
	store := NewMemStore()
	engine := NewEngine(store, zerolog.Nop())

	findings := []*corr.RawFinding{
		{ID: "s1", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeSAST, CWEID: 89, Severity: "high", Confidence: "medium", FilePath: "dao.go", LineStart: 10, FoundAt: time.Now()},
		{ID: "s2", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeSAST, CWEID: 79, Severity: "high", Confidence: "medium", FilePath: "handler.go", LineStart: 25, FoundAt: time.Now()},
	}

	run, err := engine.ProcessScan(context.Background(), "scan1", "proj1", findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if run.InputFindings != 2 {
		t.Errorf("input = %d, want 2", run.InputFindings)
	}
	// No DAST findings → no correlation groups
	if run.Correlated != 0 {
		t.Errorf("correlated = %d, want 0 (SAST-only)", run.Correlated)
	}
	if store.FindingCount() != 2 {
		t.Errorf("stored findings = %d, want 2", store.FindingCount())
	}
}

func TestEngine_ProcessScan_CrossCorrelation(t *testing.T) {
	store := NewMemStore()
	engine := NewEngine(store, zerolog.Nop())

	now := time.Now()
	findings := []*corr.RawFinding{
		{ID: "s1", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeSAST, CWEID: 89, Severity: "high", Confidence: "medium", FilePath: "internal/users/dao.go", LineStart: 47, CodeSnippet: `query := "SELECT * FROM users WHERE id = " + id`, FoundAt: now},
		{ID: "d1", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeDAST, CWEID: 89, Severity: "critical", Confidence: "medium", URL: "https://example.com/api/v1/users/123", Method: "GET", Parameter: "id", Category: "sqli", FoundAt: now},
	}

	run, err := engine.ProcessScan(context.Background(), "scan1", "proj1", findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if run.Correlated == 0 {
		t.Fatal("expected at least one correlation group")
	}

	groups := store.Groups()
	if len(groups) == 0 {
		t.Fatal("no correlation groups saved")
	}

	group := groups[0]
	if group.Confidence == corr.ConfidenceNone {
		t.Error("expected non-none confidence")
	}
	if len(group.Members) != 2 {
		t.Errorf("group members = %d, want 2", len(group.Members))
	}
	if group.RiskScore <= 0 {
		t.Error("expected positive risk score")
	}

	t.Logf("Correlation: score=%.3f confidence=%s risk=%.2f", group.Score, group.Confidence, group.RiskScore)
}

func TestEngine_ProcessScan_Deduplication(t *testing.T) {
	store := NewMemStore()
	engine := NewEngine(store, zerolog.Nop())

	finding := &corr.RawFinding{
		ID: "s1", ProjectID: "proj1", ScanJobID: "scan1",
		Type: corr.TypeSAST, CWEID: 89, Severity: "high", Confidence: "medium",
		FilePath: "dao.go", LineStart: 10, FoundAt: time.Now(),
	}

	// First scan
	engine.ProcessScan(context.Background(), "scan1", "proj1", []*corr.RawFinding{finding})
	if store.FindingCount() != 1 {
		t.Fatalf("after first scan: findings = %d, want 1", store.FindingCount())
	}

	// Second scan with same finding
	finding2 := *finding
	finding2.ScanJobID = "scan2"
	engine.ProcessScan(context.Background(), "scan2", "proj1", []*corr.RawFinding{&finding2})

	// Should still be 1 finding (deduped)
	if store.FindingCount() != 1 {
		t.Errorf("after second scan: findings = %d, want 1 (deduped)", store.FindingCount())
	}
}

func TestEngine_ProcessScan_NoFindings(t *testing.T) {
	store := NewMemStore()
	engine := NewEngine(store, zerolog.Nop())

	run, err := engine.ProcessScan(context.Background(), "scan1", "proj1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.InputFindings != 0 {
		t.Errorf("input = %d, want 0", run.InputFindings)
	}
}

func TestEngine_ProcessScan_MultipleDASTOneSAST(t *testing.T) {
	store := NewMemStore()
	engine := NewEngine(store, zerolog.Nop())

	now := time.Now()
	findings := []*corr.RawFinding{
		{ID: "s1", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeSAST, CWEID: 89, Severity: "high", Confidence: "medium", FilePath: "internal/users/dao.go", CodeSnippet: `db.Query("SELECT * FROM users WHERE id="+id)`, FoundAt: now},
		{ID: "d1", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeDAST, CWEID: 89, Severity: "critical", Confidence: "medium", URL: "https://app.com/api/users", Parameter: "id", FoundAt: now},
		{ID: "d2", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeDAST, CWEID: 89, Severity: "high", Confidence: "low", URL: "https://app.com/api/users/search", Parameter: "q", FoundAt: now},
	}

	run, err := engine.ProcessScan(context.Background(), "scan1", "proj1", findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both DAST findings should correlate with the SAST finding
	if run.Correlated < 1 {
		t.Errorf("expected correlations, got %d", run.Correlated)
	}
	t.Logf("Groups created: %d", run.Correlated)
}

func TestEngine_ProcessScan_WeakCorrelation(t *testing.T) {
	store := NewMemStore()
	engine := NewEngine(store, zerolog.Nop())

	now := time.Now()
	findings := []*corr.RawFinding{
		// SAST: XSS in auth module
		{ID: "s1", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeSAST, CWEID: 79, Severity: "medium", Confidence: "medium", FilePath: "internal/auth/login.go", CodeSnippet: `fmt.Fprintf(w, "Hello %s", username)`, FoundAt: now},
		// DAST: SQL injection in users module — different CWE, different module
		{ID: "d1", ProjectID: "proj1", ScanJobID: "scan1", Type: corr.TypeDAST, CWEID: 89, Severity: "critical", Confidence: "high", URL: "https://app.com/api/orders", Parameter: "order_id", FoundAt: now},
	}

	run, err := engine.ProcessScan(context.Background(), "scan1", "proj1", findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Low or no correlation expected — different CWE categories, different endpoints
	groups := store.Groups()
	for _, g := range groups {
		if g.Confidence == corr.ConfidenceHigh {
			t.Error("expected weak or no correlation for unrelated findings, got HIGH")
		}
	}
	t.Logf("Weak correlation test: %d groups, %d correlated", len(groups), run.Correlated)
}
