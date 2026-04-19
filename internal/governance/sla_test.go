package governance

import (
	"context"
	"testing"
	"time"
)

func TestCalculateSLADeadline(t *testing.T) {
	created := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	settings := &OrgSettings{
		DefaultFindingSLADays: map[string]int{
			"critical": 3,
			"high":     7,
			"medium":   30,
			"low":      90,
		},
	}

	tests := []struct {
		severity string
		wantDays int
	}{
		{"critical", 3},
		{"high", 7},
		{"medium", 30},
		{"low", 90},
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			deadline := CalculateSLADeadline(created, tc.severity, settings)
			expected := created.Add(time.Duration(tc.wantDays) * 24 * time.Hour)
			if !deadline.Equal(expected) {
				t.Errorf("severity=%s: expected %v, got %v", tc.severity, expected, deadline)
			}
		})
	}
}

func TestCalculateSLADeadline_UnknownSeverity(t *testing.T) {
	created := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	settings := &OrgSettings{
		DefaultFindingSLADays: map[string]int{
			"critical": 3,
			"high":     7,
		},
	}

	deadline := CalculateSLADeadline(created, "informational", settings)
	expected := created.Add(90 * 24 * time.Hour)
	if !deadline.Equal(expected) {
		t.Errorf("unknown severity: expected %v (90 days), got %v", expected, deadline)
	}
}

func TestCalculateSLADeadline_NilSettings(t *testing.T) {
	created := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	deadline := CalculateSLADeadline(created, "high", nil)
	expected := created.Add(90 * 24 * time.Hour)
	if !deadline.Equal(expected) {
		t.Errorf("nil settings: expected %v (90 days default), got %v", expected, deadline)
	}
}

func TestCheckSLAViolations_NilPool(t *testing.T) {
	_, err := CheckSLAViolations(context.Background(), nil, time.Now())
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestRecordSLAViolation_NilPool(t *testing.T) {
	v := &SLAViolation{FindingID: "f-1", OrgID: "org-1"}
	err := RecordSLAViolation(context.Background(), nil, v)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestRecordSLAViolation_NilViolation(t *testing.T) {
	err := RecordSLAViolation(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected error for nil violation")
	}
}

func TestCheckSLAWarnings_NilPool(t *testing.T) {
	_, err := CheckSLAWarnings(context.Background(), nil, time.Now())
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}
