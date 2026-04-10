package risk

import (
	"time"
)

// FingerprintVersion is the current fingerprint schema version. Bump this
// constant when fingerprint inputs or normalization rules change. Old
// clusters with the previous version continue to coexist via the
// UNIQUE (project_id, fingerprint_version, fingerprint) constraint.
const FingerprintVersion int16 = 1

// Finding is the minimal shape of a SentinelCore finding that the risk
// correlator needs. It is populated from findings.findings via the store.
type Finding struct {
	ID            string
	ProjectID     string
	ScanJobID     string
	Type          string // 'sast' | 'dast' | 'sca'
	RuleID        string
	Title         string
	CWEID         int
	OWASPCategory string
	Severity      string
	Confidence    string
	Language      string // SAST only
	FilePath      string // SAST only
	LineStart     int    // SAST only
	FunctionName  string // SAST only; may be empty
	URL           string // DAST only
	HTTPMethod    string // DAST only
	Parameter     string // DAST only
}

// Cluster is an in-memory representation of risk.clusters.
type Cluster struct {
	ID                 string
	ProjectID          string
	Fingerprint        string
	FingerprintVersion int16
	FingerprintKind    string // 'dast_route' | 'sast_file'
	Title              string
	VulnClass          string
	CWEID              int
	OWASPCategory      string
	Language           string
	CanonicalRoute     string
	CanonicalParam     string
	HTTPMethod         string
	FilePath           string
	EnclosingMethod    string
	LocationGroup      string
	Severity           string
	RiskScore          int
	Exposure           string
	Status             string
	MissingRunCount    int
	FindingCount       int
	SurfaceCount       int
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
	LastRunID          string
}

// ClusterFinding is a row in risk.cluster_findings.
type ClusterFinding struct {
	ClusterID      string
	FindingID      string
	Role           string
	FirstSeenRunID string
	LastSeenRunID  string
}

// Evidence is a row in risk.cluster_evidence.
type Evidence struct {
	ID          string
	ClusterID   string
	Category    string // 'score_base' | 'score_boost' | 'score_penalty' | 'link' | 'context'
	Code        string // 'SEVERITY_BASE' | 'RUNTIME_CONFIRMED' | ...
	Label       string
	Weight      *int // nullable for link/context rows
	RefType     string
	RefID       string
	SortOrder   int
	SourceRunID string
	Metadata    map[string]any
}

// Relation is a row in risk.cluster_relations.
type Relation struct {
	ID              string
	ProjectID       string
	SourceClusterID string
	TargetClusterID string
	RelationType    string // 'runtime_confirmation' | 'same_cwe' | 'related_surface'
	Confidence      float64
	Rationale       string
	LastLinkedRunID string
}

// Run is a row in risk.correlation_runs.
type Run struct {
	ID                string
	ProjectID         string
	Trigger           string // 'scan_completed' | 'manual' | 'retry'
	TriggeredByScan   *string
	StartedAt         time.Time
	FinishedAt        *time.Time
	Status            string // 'running' | 'ok' | 'error'
	ErrorMessage      string
	ClustersTouched   int
	ClustersCreated   int
	ClustersResolved  int
	FindingsProcessed int
}

// SurfaceEntry is the minimal surface-entry shape needed for scoring.
// Populated from scans.surface_entries via the store.
type SurfaceEntry struct {
	ID       string
	URL      string
	Method   string
	Exposure string // 'public' | 'authenticated' | 'both' | 'unknown'
}
