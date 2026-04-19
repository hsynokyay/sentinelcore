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
	ID            string `json:"id"`
	ProjectID     string `json:"project_id"`
	ScanJobID     string `json:"scan_job_id"`
	Type          string `json:"finding_type"` // 'sast' | 'dast' | 'sca'
	RuleID        string `json:"rule_id,omitempty"`
	Title         string `json:"title"`
	CWEID         int    `json:"cwe_id,omitempty"`
	OWASPCategory string `json:"owasp_category,omitempty"`
	Severity      string `json:"severity"`
	Confidence    string `json:"confidence,omitempty"` // 'low' | 'medium' | 'high' — string enum here, distinct from engine.Finding.Confidence (float64)
	Language      string `json:"language,omitempty"`   // SAST only
	FilePath      string `json:"file_path,omitempty"`  // SAST only
	LineStart     int    `json:"line_start,omitempty"` // SAST only
	FunctionName  string `json:"function_name,omitempty"` // SAST only; may be empty
	URL           string `json:"url,omitempty"`         // DAST only
	HTTPMethod    string `json:"http_method,omitempty"` // DAST only
	Parameter     string `json:"parameter,omitempty"`   // DAST only
}

// Cluster is an in-memory representation of risk.clusters.
type Cluster struct {
	ID                 string     `json:"id"`
	ProjectID          string     `json:"project_id"`
	Fingerprint        string     `json:"fingerprint"`
	FingerprintVersion int16      `json:"fingerprint_version"`
	FingerprintKind    string     `json:"fingerprint_kind"` // 'dast_route' | 'sast_file'
	Title              string     `json:"title"`
	VulnClass          string     `json:"vuln_class,omitempty"`
	CWEID              int        `json:"cwe_id,omitempty"`
	OWASPCategory      string     `json:"owasp_category,omitempty"`
	Language           string     `json:"language,omitempty"`
	CanonicalRoute     string     `json:"canonical_route,omitempty"`
	CanonicalParam     string     `json:"canonical_param,omitempty"`
	HTTPMethod         string     `json:"http_method,omitempty"`
	FilePath           string     `json:"file_path,omitempty"`
	EnclosingMethod    string     `json:"enclosing_method,omitempty"`
	LocationGroup      string     `json:"location_group,omitempty"`
	Severity           string     `json:"severity"`
	RiskScore          int        `json:"risk_score,omitempty"`
	Exposure           string     `json:"exposure,omitempty"`
	Status             string     `json:"status"`
	MissingRunCount    int        `json:"missing_run_count,omitempty"`
	FindingCount       int        `json:"finding_count,omitempty"`
	SurfaceCount       int        `json:"surface_count,omitempty"`
	FirstSeenAt        time.Time  `json:"first_seen_at"`
	LastSeenAt         time.Time  `json:"last_seen_at"`
	LastRunID          string     `json:"last_run_id,omitempty"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy         *string    `json:"resolved_by,omitempty"`
	ResolutionReason   string     `json:"resolution_reason,omitempty"`
	MutedUntil         *time.Time `json:"muted_until,omitempty"`
}

// ClusterFinding is a row in risk.cluster_findings.
type ClusterFinding struct {
	ClusterID      string `json:"cluster_id"`
	FindingID      string `json:"finding_id"`
	Role           string `json:"role,omitempty"`
	FirstSeenRunID string `json:"first_seen_run_id,omitempty"`
	LastSeenRunID  string `json:"last_seen_run_id,omitempty"`
}

// Evidence is a row in risk.cluster_evidence.
type Evidence struct {
	ID          string         `json:"id"`
	ClusterID   string         `json:"cluster_id"`
	Category    string         `json:"category"` // 'score_base' | 'score_boost' | 'score_penalty' | 'link' | 'context'
	Code        string         `json:"code"`     // 'SEVERITY_BASE' | 'RUNTIME_CONFIRMED' | ...
	Label       string         `json:"label,omitempty"`
	Weight      *int           `json:"weight,omitempty"` // nullable for link/context rows
	RefType     string         `json:"ref_type,omitempty"`
	RefID       string         `json:"ref_id,omitempty"`
	SortOrder   int            `json:"sort_order,omitempty"`
	SourceRunID string         `json:"source_run_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Relation is a row in risk.cluster_relations.
type Relation struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"project_id"`
	SourceClusterID string    `json:"source_cluster_id"`
	TargetClusterID string    `json:"target_cluster_id"`
	RelationType    string    `json:"relation_type"` // 'runtime_confirmation' | 'same_cwe' | 'related_surface'
	Confidence      float64   `json:"confidence,omitempty"`
	Rationale       string    `json:"rationale,omitempty"`
	FirstLinkedAt   time.Time `json:"first_linked_at"`
	LastLinkedRunID string    `json:"last_linked_run_id,omitempty"`
}

// Run is a row in risk.correlation_runs.
type Run struct {
	ID                string     `json:"id"`
	ProjectID         string     `json:"project_id"`
	Trigger           string     `json:"trigger"` // 'scan_completed' | 'manual' | 'retry'
	TriggeredByScan   *string    `json:"triggered_by_scan,omitempty"`
	StartedAt         time.Time  `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	Status            string     `json:"status"` // 'running' | 'ok' | 'error'
	ErrorMessage      string     `json:"error_message,omitempty"`
	ClustersTouched   int        `json:"clusters_touched,omitempty"`
	ClustersCreated   int        `json:"clusters_created,omitempty"`
	ClustersResolved  int        `json:"clusters_resolved,omitempty"`
	FindingsProcessed int        `json:"findings_processed,omitempty"`
}

// SurfaceEntry is the minimal surface-entry shape needed for scoring.
// Populated from scans.surface_entries via the store.
type SurfaceEntry struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Method   string `json:"method"`
	Exposure string `json:"exposure"` // 'public' | 'authenticated' | 'both' | 'unknown'
}
