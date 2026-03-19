// Package correlation implements the SentinelCore correlation engine that
// unifies SAST, DAST, and vulnerability intelligence findings into
// high-confidence, deduplicated, risk-scored security findings.
package correlation

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	corr "github.com/sentinelcore/sentinelcore/pkg/correlation"
)

// Engine orchestrates the correlation pipeline: ingest → dedup → correlate → score → publish.
type Engine struct {
	hierarchy *corr.CWEHierarchy
	cfg       corr.MatchConfig
	store     FindingStore
	logger    zerolog.Logger
}

// FindingStore abstracts persistence for findings and correlation groups.
// In production, backed by PostgreSQL. In tests, backed by in-memory store.
type FindingStore interface {
	// LoadProjectFindings returns all existing findings for a project.
	LoadProjectFindings(ctx context.Context, projectID string) ([]*corr.RawFinding, error)
	// UpsertFinding inserts or updates a finding based on fingerprint.
	// Returns (existingID, isNew, newScanCount).
	UpsertFinding(ctx context.Context, f *corr.RawFinding) (string, bool, int, error)
	// SaveCorrelationGroup persists a correlation group.
	SaveCorrelationGroup(ctx context.Context, group *corr.CorrelationGroup) error
	// SaveCorrelationRun records correlation run metadata.
	SaveCorrelationRun(ctx context.Context, run *corr.CorrelationRun) error
}

// NewEngine creates a correlation engine.
func NewEngine(store FindingStore, logger zerolog.Logger) *Engine {
	return &Engine{
		hierarchy: corr.DefaultCWEHierarchy(),
		cfg:       corr.DefaultMatchConfig(),
		store:     store,
		logger:    logger.With().Str("component", "correlation-engine").Logger(),
	}
}

// ProcessScan runs the full correlation pipeline for a completed scan.
func (e *Engine) ProcessScan(ctx context.Context, scanJobID, projectID string, newFindings []*corr.RawFinding) (*corr.CorrelationRun, error) {
	start := time.Now()
	run := &corr.CorrelationRun{
		ID:            uuid.New().String(),
		ScanJobID:     scanJobID,
		ProjectID:     projectID,
		InputFindings: len(newFindings),
	}

	e.logger.Info().
		Str("scan_job_id", scanJobID).
		Int("input_findings", len(newFindings)).
		Msg("starting correlation run")

	// Phase 1: Dedup new findings
	dedupResults := e.dedup(ctx, newFindings)
	run.Deduplicated = countNew(dedupResults)

	// Phase 2: Load existing project findings for cross-correlation
	existing, err := e.store.LoadProjectFindings(ctx, projectID)
	if err != nil {
		e.logger.Error().Err(err).Msg("failed to load existing findings")
		// Continue with just new findings
		existing = nil
	}

	// Phase 3: Cross-type correlation (SAST ↔ DAST)
	groups := e.correlate(newFindings, existing)
	run.Correlated = len(groups)
	run.NewGroups = len(groups) // simplified: all new in MVP

	// Phase 4: Persist groups
	for _, group := range groups {
		if err := e.store.SaveCorrelationGroup(ctx, group); err != nil {
			e.logger.Error().Err(err).Str("group_id", group.ID).Msg("failed to save group")
		}
	}

	run.Duration = time.Since(start)

	// Phase 5: Record run
	if err := e.store.SaveCorrelationRun(ctx, run); err != nil {
		e.logger.Error().Err(err).Msg("failed to save correlation run")
	}

	e.logger.Info().
		Str("scan_job_id", scanJobID).
		Int("deduplicated", run.Deduplicated).
		Int("correlated", run.Correlated).
		Dur("duration", run.Duration).
		Msg("correlation run completed")

	return run, nil
}

// dedup computes fingerprints and upserts findings.
func (e *Engine) dedup(ctx context.Context, findings []*corr.RawFinding) []corr.DedupResult {
	results := make([]corr.DedupResult, 0, len(findings))

	for _, f := range findings {
		f.ComputeFingerprint()

		existingID, isNew, scanCount, err := e.store.UpsertFinding(ctx, f)
		if err != nil {
			e.logger.Error().Err(err).Str("fingerprint", f.Fingerprint).Msg("dedup upsert failed")
			continue
		}

		results = append(results, corr.DedupResult{
			Finding:    f,
			IsNew:      isNew,
			ExistingID: existingID,
			ScanCount:  scanCount,
		})
	}

	return results
}

// correlate performs cross-type matching between SAST and DAST findings.
func (e *Engine) correlate(newFindings []*corr.RawFinding, existing []*corr.RawFinding) []*corr.CorrelationGroup {
	// Partition findings by type
	allFindings := append(newFindings, existing...)
	var sast, dast []*corr.RawFinding
	for _, f := range allFindings {
		switch f.Type {
		case corr.TypeSAST:
			sast = append(sast, f)
		case corr.TypeDAST:
			dast = append(dast, f)
		}
	}

	if len(sast) == 0 || len(dast) == 0 {
		return nil // no cross-correlation possible
	}

	var groups []*corr.CorrelationGroup

	// For each DAST finding, find best matching SAST finding
	for _, d := range dast {
		var bestSAST *corr.RawFinding
		var bestScores corr.AxisScores
		var bestTotal float64

		for _, s := range sast {
			scores, total := corr.ComputeCorrelationScore(s, d, e.hierarchy, e.cfg)
			if total > bestTotal {
				bestTotal = total
				bestScores = scores
				bestSAST = s
			}
		}

		confidence := corr.ScoreToConfidence(bestTotal)
		if confidence == corr.ConfidenceNone || bestSAST == nil {
			continue
		}

		// Compute risk score using the higher severity of the pair
		severity := d.Severity
		if severityRank(bestSAST.Severity) > severityRank(severity) {
			severity = bestSAST.Severity
		}
		riskScore := corr.ComputeRiskScore(severity, false, false, confidence, "medium")

		group := &corr.CorrelationGroup{
			ID:               uuid.New().String(),
			ProjectID:        d.ProjectID,
			PrimaryFindingID: d.ID,
			Score:            bestTotal,
			Confidence:       confidence,
			RiskScore:        riskScore,
			Members: []corr.CorrelationMember{
				{FindingID: d.ID, Type: corr.TypeDAST, AxisScores: bestScores},
				{FindingID: bestSAST.ID, Type: corr.TypeSAST, AxisScores: bestScores},
			},
			Status:    "active",
			CreatedAt: time.Now(),
		}

		groups = append(groups, group)
	}

	return groups
}

func countNew(results []corr.DedupResult) int {
	count := 0
	for _, r := range results {
		if r.IsNew {
			count++
		}
	}
	return count
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
