package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

// reportFilters holds common optional query parameters for report endpoints.
type reportFilters struct {
	ProjectID string
	TeamID    string
	DateFrom  string
	DateTo    string
}

func parseReportFilters(r *http.Request) reportFilters {
	return reportFilters{
		ProjectID: r.URL.Query().Get("project_id"),
		TeamID:    r.URL.Query().Get("team_id"),
		DateFrom:  r.URL.Query().Get("date_from"),
		DateTo:    r.URL.Query().Get("date_to"),
	}
}

// FindingsSummary returns findings grouped by severity, status, and finding_type.
func (h *Handlers) FindingsSummary(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "reports.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	filters := parseReportFilters(r)

	type summaryRow struct {
		Severity    string `json:"severity"`
		Status      string `json:"status"`
		FindingType string `json:"finding_type"`
		Count       int    `json:"count"`
	}

	var results []summaryRow

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		query := `SELECT severity, status, finding_type, COUNT(*) AS count
				  FROM findings.findings WHERE 1=1`
		args := []any{}
		argIdx := 1

		if filters.ProjectID != "" {
			query += fmt.Sprintf(" AND project_id = $%d", argIdx)
			args = append(args, filters.ProjectID)
			argIdx++
		}
		if filters.DateFrom != "" {
			query += fmt.Sprintf(" AND created_at >= $%d", argIdx)
			args = append(args, filters.DateFrom)
			argIdx++
		}
		if filters.DateTo != "" {
			query += fmt.Sprintf(" AND created_at <= $%d", argIdx)
			args = append(args, filters.DateTo)
			argIdx++
		}

		query += " GROUP BY severity, status, finding_type ORDER BY count DESC"

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var row summaryRow
			if err := rows.Scan(&row.Severity, &row.Status, &row.FindingType, &row.Count); err != nil {
				return err
			}
			results = append(results, row)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get findings summary")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if results == nil {
		results = []summaryRow{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"summary": results})
}

// TriageMetrics returns triage-related metrics: open/closed counts, assignment counts, SLA compliance.
func (h *Handlers) TriageMetrics(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "reports.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	filters := parseReportFilters(r)

	type triageResult struct {
		OpenFindings     int `json:"open_findings"`
		ClosedFindings   int `json:"closed_findings"`
		AssignedFindings int `json:"assigned_findings"`
		SLACompliant     int `json:"sla_compliant"`
		SLAViolated      int `json:"sla_violated"`
	}

	var result triageResult

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		// Open findings
		openQuery := `SELECT COUNT(*) FROM findings.findings WHERE status NOT IN ('resolved','closed','false_positive')`
		openArgs := []any{}
		openArgIdx := 1
		if filters.ProjectID != "" {
			openQuery += fmt.Sprintf(" AND project_id = $%d", openArgIdx)
			openArgs = append(openArgs, filters.ProjectID)
			openArgIdx++
		}
		if filters.DateFrom != "" {
			openQuery += fmt.Sprintf(" AND created_at >= $%d", openArgIdx)
			openArgs = append(openArgs, filters.DateFrom)
			openArgIdx++
		}
		if filters.DateTo != "" {
			openQuery += fmt.Sprintf(" AND created_at <= $%d", openArgIdx)
			openArgs = append(openArgs, filters.DateTo)
		}
		if err := tx.QueryRow(ctx, openQuery, openArgs...).Scan(&result.OpenFindings); err != nil {
			return err
		}

		// Closed findings
		closedQuery := `SELECT COUNT(*) FROM findings.findings WHERE status IN ('resolved','closed','false_positive')`
		closedArgs := []any{}
		closedArgIdx := 1
		if filters.ProjectID != "" {
			closedQuery += fmt.Sprintf(" AND project_id = $%d", closedArgIdx)
			closedArgs = append(closedArgs, filters.ProjectID)
			closedArgIdx++
		}
		if filters.DateFrom != "" {
			closedQuery += fmt.Sprintf(" AND created_at >= $%d", closedArgIdx)
			closedArgs = append(closedArgs, filters.DateFrom)
			closedArgIdx++
		}
		if filters.DateTo != "" {
			closedQuery += fmt.Sprintf(" AND created_at <= $%d", closedArgIdx)
			closedArgs = append(closedArgs, filters.DateTo)
		}
		if err := tx.QueryRow(ctx, closedQuery, closedArgs...).Scan(&result.ClosedFindings); err != nil {
			return err
		}

		// Assigned findings
		assignedQuery := `SELECT COUNT(*) FROM findings.findings WHERE assigned_to IS NOT NULL`
		assignedArgs := []any{}
		assignedArgIdx := 1
		if filters.ProjectID != "" {
			assignedQuery += fmt.Sprintf(" AND project_id = $%d", assignedArgIdx)
			assignedArgs = append(assignedArgs, filters.ProjectID)
			assignedArgIdx++
		}
		if err := tx.QueryRow(ctx, assignedQuery, assignedArgs...).Scan(&result.AssignedFindings); err != nil {
			return err
		}

		// SLA compliance from governance schema
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM governance.sla_violations WHERE resolved_at IS NOT NULL`).Scan(&result.SLACompliant); err != nil {
			// Table might not exist yet; treat as zero
			result.SLACompliant = 0
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM governance.sla_violations WHERE resolved_at IS NULL`).Scan(&result.SLAViolated); err != nil {
			result.SLAViolated = 0
		}

		return nil
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get triage metrics")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ComplianceStatus returns audit log stats, retention compliance, and SLA compliance percentages.
func (h *Handlers) ComplianceStatus(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "reports.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	type complianceResult struct {
		AuditLogCount       int     `json:"audit_log_count"`
		RetentionActive     int     `json:"retention_active"`
		RetentionArchived   int     `json:"retention_archived"`
		RetentionPurged     int     `json:"retention_purged"`
		SLACompliancePct    float64 `json:"sla_compliance_pct"`
		FindingsWithinSLA   int     `json:"findings_within_sla"`
		FindingsBreachedSLA int     `json:"findings_breached_sla"`
	}

	var result complianceResult

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		// Audit log count
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM audit.audit_log`).Scan(&result.AuditLogCount); err != nil {
			result.AuditLogCount = 0
		}

		// Retention record counts by lifecycle
		rows, err := tx.Query(ctx, `SELECT lifecycle, COUNT(*) FROM governance.retention_records GROUP BY lifecycle`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var lifecycle string
				var count int
				if err := rows.Scan(&lifecycle, &count); err != nil {
					continue
				}
				switch lifecycle {
				case "active":
					result.RetentionActive = count
				case "archived":
					result.RetentionArchived = count
				case "purged":
					result.RetentionPurged = count
				}
			}
		}

		// SLA compliance
		var totalSLA, resolvedSLA int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM governance.sla_violations`).Scan(&totalSLA); err != nil {
			totalSLA = 0
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM governance.sla_violations WHERE resolved_at IS NOT NULL`).Scan(&resolvedSLA); err != nil {
			resolvedSLA = 0
		}
		result.FindingsWithinSLA = resolvedSLA
		result.FindingsBreachedSLA = totalSLA - resolvedSLA
		if totalSLA > 0 {
			result.SLACompliancePct = float64(resolvedSLA) / float64(totalSLA) * 100
		} else {
			result.SLACompliancePct = 100
		}

		return nil
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get compliance status")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ScanActivity returns scan counts by type, average duration, and coverage stats.
func (h *Handlers) ScanActivity(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "reports.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	filters := parseReportFilters(r)

	type scanStat struct {
		ScanType string  `json:"scan_type"`
		Count    int     `json:"count"`
		AvgDurS  float64 `json:"avg_duration_seconds"`
	}

	var results []scanStat

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID, func(ctx context.Context, tx pgx.Tx) error {
		query := `SELECT scan_type, COUNT(*) AS count,
				  COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at))), 0) AS avg_dur
				  FROM scans.scan_jobs WHERE 1=1`
		args := []any{}
		argIdx := 1

		if filters.ProjectID != "" {
			query += fmt.Sprintf(" AND project_id = $%d", argIdx)
			args = append(args, filters.ProjectID)
			argIdx++
		}
		if filters.DateFrom != "" {
			query += fmt.Sprintf(" AND created_at >= $%d", argIdx)
			args = append(args, filters.DateFrom)
			argIdx++
		}
		if filters.DateTo != "" {
			query += fmt.Sprintf(" AND created_at <= $%d", argIdx)
			args = append(args, filters.DateTo)
			argIdx++
		}

		query += " GROUP BY scan_type ORDER BY count DESC"

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var s scanStat
			if err := rows.Scan(&s.ScanType, &s.Count, &s.AvgDurS); err != nil {
				return err
			}
			results = append(results, s)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get scan activity")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if results == nil {
		results = []scanStat{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"scan_activity": results})
}
