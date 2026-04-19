package correlation

import (
	"testing"
	"time"
)

func TestScoreCWEAxis(t *testing.T) {
	h := DefaultCWEHierarchy()

	tests := []struct {
		name string
		a, b int
		want float64
	}{
		{"exact match", 89, 89, 1.0},
		{"parent match", 89, 943, 0.5},
		{"child match", 943, 89, 0.5},
		{"shared parent", 78, 77, 0.5},
		{"same category", 89, 79, 0.3},  // both injection
		{"no match", 89, 352, 0.0},       // SQL injection vs CSRF
		{"zero CWE", 0, 89, 0.0},
		{"both zero", 0, 0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScoreCWEAxis(tt.a, tt.b, h)
			if got != tt.want {
				t.Errorf("ScoreCWEAxis(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestScoreParameterAxis(t *testing.T) {
	tests := []struct {
		name    string
		snippet string
		param   string
		want    float64
	}{
		{"exact match", `query := "SELECT * FROM users WHERE id = " + id`, "id", 1.0},
		{"no match", `query := "SELECT * FROM users"`, "email", 0.0},
		{"empty param", `some code`, "", 0.0},
		{"empty snippet", "", "id", 0.0},
		{"normalized snake to camel", `userId := request.Param("userId")`, "user_id", 0.7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScoreParameterAxis(tt.snippet, tt.param)
			if got != tt.want {
				t.Errorf("ScoreParameterAxis(%q, %q) = %v, want %v", tt.snippet, tt.param, got, tt.want)
			}
		})
	}
}

func TestScoreEndpointAxis(t *testing.T) {
	tests := []struct {
		name     string
		dastURL  string
		sastPath string
		wantMin  float64
	}{
		{"matching resource", "https://example.com/api/v1/users/123", "internal/users/handler.go", 0.4},
		{"no match", "https://example.com/api/v1/orders", "internal/auth/login.go", 0.0},
		{"empty url", "", "internal/users/handler.go", 0.0},
		{"empty path", "https://example.com/api/users", "", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScoreEndpointAxis(tt.dastURL, tt.sastPath)
			if got < tt.wantMin {
				t.Errorf("ScoreEndpointAxis(%q, %q) = %v, want >= %v", tt.dastURL, tt.sastPath, got, tt.wantMin)
			}
		})
	}
}

func TestScoreTemporalAxis(t *testing.T) {
	now := time.Now()
	cfg := DefaultMatchConfig()

	tests := []struct {
		name string
		a, b time.Time
		want float64
	}{
		{"same time", now, now, 1.0},
		{"30 min apart", now, now.Add(-30 * time.Minute), 1.0},
		{"12 hours apart", now, now.Add(-12 * time.Hour), 0.8},
		{"3 days apart", now, now.Add(-72 * time.Hour), 0.5},
		{"30 days apart", now, now.Add(-30 * 24 * time.Hour), 0.2},
		{"zero times", time.Time{}, time.Time{}, 0.2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScoreTemporalAxis(tt.a, tt.b, cfg)
			if got != tt.want {
				t.Errorf("ScoreTemporalAxis = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeCorrelationScore(t *testing.T) {
	h := DefaultCWEHierarchy()
	cfg := DefaultMatchConfig()
	now := time.Now()

	sast := &RawFinding{
		Type:        TypeSAST,
		CWEID:       89,
		FilePath:    "internal/users/dao.go",
		CodeSnippet: `query := "SELECT * FROM users WHERE id = " + id`,
		FoundAt:     now,
	}
	dast := &RawFinding{
		Type:      TypeDAST,
		CWEID:     89,
		URL:       "https://example.com/api/v1/users/123",
		Parameter: "id",
		FoundAt:   now,
	}

	scores, total := ComputeCorrelationScore(sast, dast, h, cfg)

	if scores.CWE != 1.0 {
		t.Errorf("CWE score = %v, want 1.0", scores.CWE)
	}
	if scores.Parameter != 1.0 {
		t.Errorf("Parameter score = %v, want 1.0", scores.Parameter)
	}
	if scores.Temporal != 1.0 {
		t.Errorf("Temporal score = %v, want 1.0", scores.Temporal)
	}
	if total < 0.80 {
		t.Errorf("total score = %v, want >= 0.80 (high confidence)", total)
	}

	confidence := ScoreToConfidence(total)
	if confidence != ConfidenceHigh {
		t.Errorf("confidence = %v, want high", confidence)
	}
}

func TestComputeRiskScore(t *testing.T) {
	tests := []struct {
		name       string
		severity   string
		exploit    bool
		active     bool
		confidence Confidence
		asset      string
		wantMin    float64
		wantMax    float64
	}{
		{"base critical", "critical", false, false, ConfidenceNone, "medium", 9.5, 9.5},
		{"critical + exploit + active + high conf", "critical", true, true, ConfidenceHigh, "critical", 10.0, 10.0},
		{"low severity no boost", "low", false, false, ConfidenceNone, "low", 1.5, 2.5},
		{"medium + correlation boost", "medium", false, false, ConfidenceHigh, "medium", 5.5, 6.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeRiskScore(tt.severity, tt.exploit, tt.active, tt.confidence, tt.asset)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("ComputeRiskScore = %v, want [%v, %v]", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestScoreToConfidence(t *testing.T) {
	tests := []struct {
		score float64
		want  Confidence
	}{
		{0.90, ConfidenceHigh},
		{0.80, ConfidenceHigh},
		{0.60, ConfidenceMedium},
		{0.50, ConfidenceMedium},
		{0.35, ConfidenceLow},
		{0.30, ConfidenceLow},
		{0.20, ConfidenceNone},
		{0.00, ConfidenceNone},
	}

	for _, tt := range tests {
		got := ScoreToConfidence(tt.score)
		if got != tt.want {
			t.Errorf("ScoreToConfidence(%v) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestRiskScoreToSeverity(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10.0, "critical"},
		{9.0, "critical"},
		{7.5, "high"},
		{5.0, "medium"},
		{2.0, "low"},
		{0.5, "info"},
	}

	for _, tt := range tests {
		got := RiskScoreToSeverity(tt.score)
		if got != tt.want {
			t.Errorf("RiskScoreToSeverity(%v) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestAxisScores_Total(t *testing.T) {
	scores := AxisScores{CWE: 1.0, Parameter: 1.0, Endpoint: 1.0, Temporal: 1.0}
	total := scores.Total()
	if total != 1.0 {
		t.Errorf("perfect scores total = %v, want 1.0", total)
	}

	zero := AxisScores{}
	if zero.Total() != 0.0 {
		t.Errorf("zero scores total = %v, want 0.0", zero.Total())
	}
}

func TestRawFinding_ComputeFingerprint(t *testing.T) {
	f1 := &RawFinding{ProjectID: "p1", Type: TypeSAST, CWEID: 89, FilePath: "a.go", LineStart: 10}
	f2 := &RawFinding{ProjectID: "p1", Type: TypeSAST, CWEID: 89, FilePath: "a.go", LineStart: 10}
	f3 := &RawFinding{ProjectID: "p1", Type: TypeSAST, CWEID: 89, FilePath: "a.go", LineStart: 20}

	fp1 := f1.ComputeFingerprint()
	fp2 := f2.ComputeFingerprint()
	fp3 := f3.ComputeFingerprint()

	if fp1 != fp2 {
		t.Error("identical findings should have same fingerprint")
	}
	if fp1 == fp3 {
		t.Error("different line should produce different fingerprint")
	}
	if len(fp1) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (SHA-256 hex)", len(fp1))
	}
}

func TestCWEHierarchy_IsRelated(t *testing.T) {
	h := DefaultCWEHierarchy()

	tests := []struct {
		a, b    int
		related bool
	}{
		{89, 89, true},   // same
		{89, 943, true},  // parent
		{89, 79, true},   // same category (injection)
		{89, 22, false},  // different category
	}

	for _, tt := range tests {
		got := h.IsRelated(tt.a, tt.b)
		if got != tt.related {
			t.Errorf("IsRelated(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.related)
		}
	}
}

func TestCamelToSnake(t *testing.T) {
	tests := []struct{ in, want string }{
		{"userId", "user_id"},
		{"id", "id"},
		{"HTTPMethod", "h_t_t_p_method"},
		{"", ""},
	}
	for _, tt := range tests {
		got := camelToSnake(tt.in)
		if got != tt.want {
			t.Errorf("camelToSnake(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSnakeToCamel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"user_id", "userId"},
		{"id", "id"},
		{"", ""},
	}
	for _, tt := range tests {
		got := snakeToCamel(tt.in)
		if got != tt.want {
			t.Errorf("snakeToCamel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
