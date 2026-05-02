// Package correlation provides core types and scoring functions for the
// SentinelCore correlation engine, which unifies SAST, DAST, and vulnerability
// intelligence findings into high-confidence security results.
package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// FindingType classifies the source scanner.
type FindingType string

const (
	TypeSAST   FindingType = "sast"
	TypeDAST   FindingType = "dast"
	TypeSCA    FindingType = "sca"
	TypeSecret FindingType = "secret"
)

// RawFinding is the unified internal representation of any scanner finding.
// It normalizes SAST, DAST, and SCA findings into a common shape.
type RawFinding struct {
	ID          string      `json:"id"`
	ProjectID   string      `json:"project_id"`
	ScanJobID   string      `json:"scan_job_id"`
	Type        FindingType `json:"finding_type"`
	RuleID      string      `json:"rule_id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	CWEID       int         `json:"cwe_id"`
	Severity    string      `json:"severity"`
	Confidence  string      `json:"confidence"`

	// SAST fields
	FilePath    string `json:"file_path,omitempty"`
	LineStart   int    `json:"line_start,omitempty"`
	LineEnd     int    `json:"line_end,omitempty"`
	CodeSnippet string `json:"code_snippet,omitempty"`

	// DAST fields
	URL       string `json:"url,omitempty"`
	Method    string `json:"http_method,omitempty"`
	Parameter string `json:"parameter,omitempty"`
	Category  string `json:"category,omitempty"`

	// SCA fields
	DependencyName    string `json:"dependency_name,omitempty"`
	DependencyVersion string `json:"dependency_version,omitempty"`
	CVEIDs            []string `json:"cve_ids,omitempty"`

	// Metadata
	Fingerprint string    `json:"fingerprint"`
	EvidenceRef string    `json:"evidence_ref,omitempty"`
	FoundAt     time.Time `json:"found_at"`
}

// ComputeFingerprint generates a stable SHA-256 fingerprint for deduplication.
func (f *RawFinding) ComputeFingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d", f.ProjectID, f.Type, f.CWEID)

	switch f.Type {
	case TypeSAST:
		fmt.Fprintf(h, "|%s|%d", f.FilePath, f.LineStart)
	case TypeDAST:
		fmt.Fprintf(h, "|%s|%s|%s", f.URL, f.Method, f.Parameter)
	case TypeSCA:
		fmt.Fprintf(h, "|%s|%s", f.DependencyName, f.CVEIDsKey())
	case TypeSecret:
		fmt.Fprintf(h, "|%s|%d", f.FilePath, f.LineStart)
	}

	f.Fingerprint = hex.EncodeToString(h.Sum(nil))
	return f.Fingerprint
}

// CVEIDsKey returns a stable string representation of CVE IDs for fingerprinting.
func (f *RawFinding) CVEIDsKey() string {
	if len(f.CVEIDs) == 0 {
		return ""
	}
	key := ""
	for i, id := range f.CVEIDs {
		if i > 0 {
			key += ","
		}
		key += id
	}
	return key
}

// AxisScores captures the per-axis match quality between two findings.
type AxisScores struct {
	CWE       float64 `json:"cwe"`
	Parameter float64 `json:"parameter"`
	Endpoint  float64 `json:"endpoint"`
	Temporal  float64 `json:"temporal"`
}

// Total computes the weighted correlation score.
func (a AxisScores) Total() float64 {
	return 0.40*a.CWE + 0.25*a.Parameter + 0.20*a.Endpoint + 0.15*a.Temporal
}

// Confidence maps the correlation score to a confidence label.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = ""
)

// ScoreToConfidence maps a correlation score to a confidence level.
func ScoreToConfidence(score float64) Confidence {
	switch {
	case score >= 0.80:
		return ConfidenceHigh
	case score >= 0.50:
		return ConfidenceMedium
	case score >= 0.30:
		return ConfidenceLow
	default:
		return ConfidenceNone
	}
}

// CorrelationGroup links related findings across scan types.
type CorrelationGroup struct {
	ID               string              `json:"id"`
	ProjectID        string              `json:"project_id"`
	PrimaryFindingID string              `json:"primary_finding_id"`
	Score            float64             `json:"correlation_score"`
	Confidence       Confidence          `json:"confidence"`
	RiskScore        float64             `json:"risk_score"`
	Members          []CorrelationMember `json:"members"`
	Status           string              `json:"status"`
	CreatedAt        time.Time           `json:"created_at"`
}

// CorrelationMember is a finding within a correlation group.
type CorrelationMember struct {
	FindingID  string     `json:"finding_id"`
	Type       FindingType `json:"finding_type"`
	AxisScores AxisScores `json:"axis_scores"`
}

// CorrelationRun records metadata about a single correlation execution.
type CorrelationRun struct {
	ID             string        `json:"id"`
	ScanJobID      string        `json:"scan_job_id"`
	ProjectID      string        `json:"project_id"`
	InputFindings  int           `json:"input_findings"`
	Deduplicated   int           `json:"deduplicated"`
	Correlated     int           `json:"correlated"`
	NewGroups      int           `json:"new_groups"`
	UpdatedGroups  int           `json:"updated_groups"`
	Duration       time.Duration `json:"duration"`
}

// DedupResult captures the outcome of deduplication for a single finding.
type DedupResult struct {
	Finding     *RawFinding
	IsNew       bool
	ExistingID  string // non-empty if deduplicated against existing
	ScanCount   int
}
