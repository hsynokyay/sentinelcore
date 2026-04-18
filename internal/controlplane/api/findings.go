package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/governance"
	"github.com/sentinelcore/sentinelcore/internal/policy"
	auditpkg "github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

type findingResponse struct {
	ID                      string             `json:"id"`
	ProjectID               string             `json:"project_id"`
	ScanID                  string             `json:"scan_id"`
	FindingType             string             `json:"finding_type"`
	Severity                string             `json:"severity"`
	Status                  string             `json:"status"`
	Title                   string             `json:"title"`
	Description             string             `json:"description"`
	FilePath                string             `json:"file_path,omitempty"`
	LineNumber              *int               `json:"line_number,omitempty"`
	CreatedAt               string             `json:"created_at"`
	SLADeadline             *string            `json:"sla_deadline,omitempty"`
	AssignedTo              *string            `json:"assigned_to,omitempty"`
	LegalHold               *bool              `json:"legal_hold,omitempty"`
	CorrelationConfidence   *string            `json:"correlation_confidence,omitempty"`
	CorrelatedFindingIDs    []string           `json:"correlated_finding_ids,omitempty"`
	StateTransitions        []stateTransition  `json:"state_transitions,omitempty"`
	TaintPaths              []taintPathStep    `json:"taint_paths,omitempty"`
	RuleID                  string             `json:"rule_id,omitempty"`
	Remediation             *remediationBlock  `json:"remediation,omitempty"`
}

// remediationBlock is the subset of the remediation pack exposed in the API.
type remediationBlock struct {
	Title                 string              `json:"title"`
	Summary               string              `json:"summary"`
	WhyItMatters          string              `json:"why_it_matters"`
	HowToFix              string              `json:"how_to_fix"`
	UnsafeExample         string              `json:"unsafe_example"`
	SafeExample           string              `json:"safe_example"`
	DeveloperNotes        string              `json:"developer_notes,omitempty"`
	VerificationChecklist []string            `json:"verification_checklist"`
	References            []remediationRef    `json:"references"`
}

type remediationRef struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type taintPathStep struct {
	StepIndex   int    `json:"step_index"`
	FilePath    string `json:"file_path"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end,omitempty"`
	StepKind    string `json:"step_kind"`
	Detail      string `json:"detail"`
	FunctionFQN string `json:"function_fqn,omitempty"`
}

type stateTransition struct {
	FromStatus string `json:"from_status"`
	ToStatus   string `json:"to_status"`
	ChangedBy  string `json:"changed_by"`
	Reason     string `json:"reason,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type updateFindingStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// ListFindings queries findings with filters, paginated and RLS-enforced.
func (h *Handlers) ListFindings(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "findings.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	// Parse query params
	projectID := r.URL.Query().Get("project_id")
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	findingType := r.URL.Query().Get("finding_type")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50
	offset := 0
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 200 {
			limit = v
		}
	}
	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
			offset = v
		}
	}

	var findings []findingResponse

	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		query := `SELECT id, project_id, scan_job_id, finding_type, severity, status, title, COALESCE(description, ''), COALESCE(file_path, ''), line_start, created_at
				  FROM findings.findings WHERE 1=1`
		args := []any{}
		argIdx := 1

		if projectID != "" {
			query += fmt.Sprintf(" AND project_id = $%d", argIdx)
			args = append(args, projectID)
			argIdx++
		}
		if severity != "" {
			query += fmt.Sprintf(" AND severity = $%d", argIdx)
			args = append(args, severity)
			argIdx++
		}
		if status != "" {
			query += fmt.Sprintf(" AND status = $%d", argIdx)
			args = append(args, status)
			argIdx++
		}
		if findingType != "" {
			query += fmt.Sprintf(" AND finding_type = $%d", argIdx)
			args = append(args, findingType)
			argIdx++
		}

		query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, limit, offset)

		rows, err := conn.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var f findingResponse
			var createdAt time.Time
			var lineNumber *int
			if err := rows.Scan(&f.ID, &f.ProjectID, &f.ScanID, &f.FindingType, &f.Severity, &f.Status, &f.Title, &f.Description, &f.FilePath, &lineNumber, &createdAt); err != nil {
				return err
			}
			f.CreatedAt = createdAt.Format(time.RFC3339)
			f.LineNumber = lineNumber
			findings = append(findings, f)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list findings")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if findings == nil {
		findings = []findingResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"findings": findings,
		"limit":    limit,
		"offset":   offset,
	})
}

// GetFinding returns a single finding by ID with RLS enforcement.
func (h *Handlers) GetFinding(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "findings.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	var f findingResponse
	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		var createdAt time.Time
		var lineNumber *int
		var slaDeadline *time.Time
		var assignedTo *string
		var legalHold *bool
		var correlationConfidence *string
		var correlatedFindingIDs []string

		var ruleID *string
		qErr := conn.QueryRow(ctx,
			`SELECT id, project_id, scan_job_id, finding_type, severity, status, title,
			        COALESCE(description, ''), COALESCE(file_path, ''), line_start, created_at,
			        sla_deadline, assigned_to, legal_hold, correlation_confidence, correlated_finding_ids,
			        rule_id
			 FROM findings.findings WHERE id = $1`, id,
		).Scan(&f.ID, &f.ProjectID, &f.ScanID, &f.FindingType, &f.Severity, &f.Status,
			&f.Title, &f.Description, &f.FilePath, &lineNumber, &createdAt,
			&slaDeadline, &assignedTo, &legalHold, &correlationConfidence, &correlatedFindingIDs,
			&ruleID)
		if qErr != nil {
			return qErr
		}

		f.CreatedAt = createdAt.Format(time.RFC3339)
		f.LineNumber = lineNumber
		if ruleID != nil {
			f.RuleID = *ruleID
		}
		if slaDeadline != nil {
			s := slaDeadline.Format(time.RFC3339)
			f.SLADeadline = &s
		}
		f.AssignedTo = assignedTo
		f.LegalHold = legalHold
		f.CorrelationConfidence = correlationConfidence
		if len(correlatedFindingIDs) > 0 {
			f.CorrelatedFindingIDs = correlatedFindingIDs
		}

		// Query state transitions
		rows, tErr := conn.Query(ctx,
			`SELECT from_status, to_status, changed_by, COALESCE(reason, ''), created_at
			 FROM findings.finding_state_transitions
			 WHERE finding_id = $1
			 ORDER BY created_at ASC`, id)
		if tErr != nil {
			return tErr
		}
		defer rows.Close()

		for rows.Next() {
			var st stateTransition
			var stCreatedAt time.Time
			if sErr := rows.Scan(&st.FromStatus, &st.ToStatus, &st.ChangedBy, &st.Reason, &stCreatedAt); sErr != nil {
				return sErr
			}
			st.CreatedAt = stCreatedAt.Format(time.RFC3339)
			f.StateTransitions = append(f.StateTransitions, st)
		}
		if rErr := rows.Err(); rErr != nil {
			return rErr
		}

		// Query taint paths (SAST evidence chain).
		tpRows, tpErr := conn.Query(ctx,
			`SELECT step_index, file_path, line_start, COALESCE(line_end, 0),
			        step_kind, detail, COALESCE(function_fqn, '')
			   FROM findings.taint_paths
			  WHERE finding_id = $1
			  ORDER BY step_index ASC`, id)
		if tpErr != nil {
			return tpErr
		}
		defer tpRows.Close()
		for tpRows.Next() {
			var tp taintPathStep
			if sErr := tpRows.Scan(&tp.StepIndex, &tp.FilePath, &tp.LineStart, &tp.LineEnd, &tp.StepKind, &tp.Detail, &tp.FunctionFQN); sErr != nil {
				return sErr
			}
			f.TaintPaths = append(f.TaintPaths, tp)
		}
		return tpRows.Err()
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "finding not found", "NOT_FOUND")
		return
	}

	// Attach remediation pack if one exists for this rule.
	if f.RuleID != "" && h.remediation != nil {
		if pack := h.remediation.Get(f.RuleID); pack != nil {
			refs := make([]remediationRef, 0, len(pack.References))
			for _, r := range pack.References {
				refs = append(refs, remediationRef{Title: r.Title, URL: r.URL})
			}
			f.Remediation = &remediationBlock{
				Title:                 pack.Title,
				Summary:               pack.Summary,
				WhyItMatters:          pack.WhyItMatters,
				HowToFix:              pack.HowToFix,
				UnsafeExample:         pack.UnsafeExample,
				SafeExample:           pack.SafeExample,
				DeveloperNotes:        pack.DeveloperNotes,
				VerificationChecklist: pack.VerificationChecklist,
				References:            refs,
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"finding": f})
}

// UpdateFindingStatus updates a finding's status and records a state transition.
func (h *Handlers) UpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "findings.triage") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	var req updateFindingStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Status == "" {
		writeError(w, http.StatusBadRequest, "status is required", "BAD_REQUEST")
		return
	}

	var oldStatus string
	var resultStatus int
	var resultBody any

	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		// Get current status under RLS
		qErr := conn.QueryRow(ctx,
			`SELECT status FROM findings.findings WHERE id = $1`, id,
		).Scan(&oldStatus)
		if qErr != nil {
			resultStatus = http.StatusNotFound
			resultBody = map[string]string{"error": "finding not found", "code": "NOT_FOUND"}
			return nil
		}

		// Validate transition
		if tErr := governance.ValidateTransition(oldStatus, req.Status); tErr != nil {
			resultStatus = http.StatusUnprocessableEntity
			resultBody = map[string]string{"error": tErr.Error(), "code": "INVALID_TRANSITION"}
			return nil
		}

		// Update status
		_, uErr := conn.Exec(ctx,
			`UPDATE findings.findings SET status = $1, updated_at = now() WHERE id = $2`,
			req.Status, id)
		if uErr != nil {
			return uErr
		}

		// Insert state transition record
		_, _ = conn.Exec(ctx,
			`INSERT INTO findings.finding_state_transitions (id, finding_id, from_status, to_status, changed_by, reason, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, now())`,
			uuid.New().String(), id, oldStatus, req.Status, user.UserID, req.Reason)

		resultStatus = http.StatusOK
		resultBody = map[string]string{"id": id, "old_status": oldStatus, "new_status": req.Status}
		return nil
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to update finding status")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if resultStatus == http.StatusOK && h.emitter != nil {
		// Canonical taxonomy: finding.status.changed. Details carry
		// the before/after so the audit consumer can render a diff.
		_ = h.emitter.Emit(r.Context(), auditpkg.AuditEvent{
			ActorType:    "user",
			ActorID:      user.UserID,
			ActorIP:      r.RemoteAddr,
			Action:       string(auditpkg.FindingStatusChanged),
			ResourceType: "finding",
			ResourceID:   id,
			OrgID:        user.OrgID,
			Result:       auditpkg.ResultSuccess,
			Details: map[string]any{
				"before": map[string]any{"status": oldStatus},
				"after":  map[string]any{"status": req.Status},
				"reason": req.Reason,
			},
		})
	}

	writeJSON(w, resultStatus, resultBody)
}
