package engine

import (
	"context"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FindingMessage is the NATS message shape the correlation handler's
// mapToRawFinding function expects. This must match the field names used in
// the existing SAST worker (internal/sast/worker.go publishResults) and the
// correlation handler's JSON key lookups.
type FindingMessage struct {
	ScanJobID   string `json:"scan_job_id"`
	ProjectID   string `json:"project_id"`
	FindingType string `json:"finding_type"`
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CWEID       int    `json:"cwe_id"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	FilePath    string `json:"file_path"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end,omitempty"`
	CodeSnippet string `json:"code_snippet,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

// ToMessage converts an engine.Finding to a FindingMessage ready for NATS
// publication. scanJobID and projectID are passed from the scan dispatch
// context.
func ToMessage(f Finding, scanJobID, projectID string) FindingMessage {
	// Parse the first CWE number: "CWE-89" → 89
	cweID := 0
	if len(f.CWE) > 0 {
		s := strings.TrimPrefix(f.CWE[0], "CWE-")
		if n, err := strconv.Atoi(s); err == nil {
			cweID = n
		}
	}

	// Bucket the float64 confidence into the high/medium/low enum the DB
	// CHECK constraint requires.
	confidence := "medium"
	if f.Confidence >= 0.75 {
		confidence = "high"
	} else if f.Confidence < 0.4 {
		confidence = "low"
	}

	// Determine finding_type from rule_id prefix or CWE class.
	findingType := "sast"
	if strings.Contains(f.RuleID, "SECRET") {
		findingType = "secret"
	}

	return FindingMessage{
		ScanJobID:   scanJobID,
		ProjectID:   projectID,
		FindingType: findingType,
		RuleID:      f.RuleID,
		Title:       f.Title,
		Description: f.Description,
		CWEID:       cweID,
		Severity:    f.Severity,
		Confidence:  confidence,
		FilePath:    f.ModulePath,
		LineStart:   f.Line,
		LineEnd:     f.EndLine,
		Fingerprint: f.Fingerprint,
	}
}

// TaintPathRow is a single row in the findings.taint_paths table.
type TaintPathRow struct {
	FindingID   string
	StepIndex   int
	FilePath    string
	LineStart   int
	LineEnd     int
	StepKind    string // "source", "propagation", "sink"
	Detail      string
	FunctionFQN string
}

// ToTaintPathRows converts an engine.Finding's evidence chain to rows ready
// for bulk insert into findings.taint_paths. findingID is the UUID of the
// parent findings.findings row.
func ToTaintPathRows(f Finding, findingID string) []TaintPathRow {
	rows := make([]TaintPathRow, 0, len(f.Evidence))
	for i, step := range f.Evidence {
		kind := "propagation"
		if i == 0 {
			kind = "source"
		}
		if i == len(f.Evidence)-1 {
			kind = "sink"
		}
		if len(f.Evidence) == 1 {
			// Single-step evidence (AST-local rules): classify as "source".
			kind = "source"
		}
		rows = append(rows, TaintPathRow{
			FindingID:   findingID,
			StepIndex:   step.StepIndex,
			FilePath:    step.ModulePath,
			LineStart:   step.Line,
			LineEnd:     step.EndLine,
			StepKind:    kind,
			Detail:      step.Description,
			FunctionFQN: step.Function,
		})
	}
	return rows
}

// InsertTaintPaths bulk-inserts taint path rows into the database. This is
// called by the SAST worker after the finding has been persisted by the
// correlation handler. The pool is used directly (not under RLS) because
// this runs in the worker context, not in a user-facing API handler.
func InsertTaintPaths(ctx context.Context, pool *pgxpool.Pool, rows []TaintPathRow) error {
	if len(rows) == 0 || pool == nil {
		return nil
	}
	for _, r := range rows {
		_, err := pool.Exec(ctx,
			`INSERT INTO findings.taint_paths
			   (id, finding_id, step_index, file_path, line_start, line_end, step_kind, detail, function_fqn)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (finding_id, step_index) DO NOTHING`,
			uuid.New().String(), r.FindingID, r.StepIndex, r.FilePath, r.LineStart, r.LineEnd, r.StepKind, r.Detail, r.FunctionFQN,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
