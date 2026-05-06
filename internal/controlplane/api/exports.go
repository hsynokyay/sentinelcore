package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/compliance"
	"github.com/sentinelcore/sentinelcore/internal/export"
	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/internal/remediation"
	"github.com/sentinelcore/sentinelcore/pkg/db"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

// ExportFindingMarkdown serves GET /api/v1/findings/{id}/export.md
func (h *Handlers) ExportFindingMarkdown(w http.ResponseWriter, r *http.Request) {
	observability.ExportRequests.WithLabelValues("markdown", "finding").Inc()
	f, ok := h.loadFindingForExport(w, r)
	if !ok {
		return
	}
	md := export.FindingMarkdown(f)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-finding.md"`, safeFilenameSlug(f.Title)))
	w.Write([]byte(md))
}

// ExportFindingSARIF serves GET /api/v1/findings/{id}/export.sarif
func (h *Handlers) ExportFindingSARIF(w http.ResponseWriter, r *http.Request) {
	observability.ExportRequests.WithLabelValues("sarif", "finding").Inc()
	f, ok := h.loadFindingForExport(w, r)
	if !ok {
		return
	}
	sarif, err := export.FindingSARIF(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SARIF generation failed", "INTERNAL_ERROR")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-finding.sarif"`, safeFilenameSlug(f.Title)))
	w.Write(sarif)
}

// ExportScanMarkdown serves GET /api/v1/scans/{id}/report.md
func (h *Handlers) ExportScanMarkdown(w http.ResponseWriter, r *http.Request) {
	observability.ExportRequests.WithLabelValues("markdown", "scan").Inc()
	d, ok := h.loadScanForExport(w, r)
	if !ok {
		return
	}
	md := export.ScanReportMarkdown(d)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-scan-report.md"`, safeFilenameSlug(d.ProjectName+"-"+d.ScanType)))
	w.Write([]byte(md))
}

// ExportScanSARIF serves GET /api/v1/scans/{id}/report.sarif
func (h *Handlers) ExportScanSARIF(w http.ResponseWriter, r *http.Request) {
	observability.ExportRequests.WithLabelValues("sarif", "scan").Inc()
	d, ok := h.loadScanForExport(w, r)
	if !ok {
		return
	}
	sarif, err := export.ScanSARIF(d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SARIF generation failed", "INTERNAL_ERROR")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-scan.sarif"`, safeFilenameSlug(d.ProjectName+"-"+d.ScanType)))
	w.Write(sarif)
}

// --- Internal loaders ---

func (h *Handlers) loadFindingForExport(w http.ResponseWriter, r *http.Request) (export.FindingData, bool) {
	user := requireAuth(w, r)
	if user == nil {
		return export.FindingData{}, false
	}
	if !policy.Evaluate(user.Role, "findings.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return export.FindingData{}, false
	}

	id := r.PathValue("id")
	var f export.FindingData
	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		var createdAt time.Time
		var lineStart *int
		var ruleID *string
		qErr := conn.QueryRow(ctx,
			`SELECT id, title, severity, status, finding_type, COALESCE(rule_id,''),
			        COALESCE(description,''), COALESCE(file_path,''), line_start,
			        COALESCE(url,''), COALESCE(http_method,''), COALESCE(parameter,''),
			        created_at
			 FROM findings.findings WHERE id = $1`, id,
		).Scan(&f.ID, &f.Title, &f.Severity, &f.Status, &f.FindingType, &ruleID,
			&f.Description, &f.FilePath, &lineStart,
			&f.URL, &f.Method, &f.Parameter, &createdAt)
		if qErr != nil {
			return qErr
		}
		if lineStart != nil {
			f.LineStart = *lineStart
		}
		if ruleID != nil {
			f.RuleID = *ruleID
		}
		f.CreatedAt = createdAt

		// Load taint paths.
		rows, tpErr := conn.Query(ctx,
			`SELECT step_index, file_path, line_start, step_kind, detail
			 FROM findings.taint_paths WHERE finding_id = $1 ORDER BY step_index`, id)
		if tpErr != nil {
			return tpErr
		}
		defer rows.Close()
		for rows.Next() {
			var s export.TaintStep
			if sErr := rows.Scan(&s.StepIndex, &s.FilePath, &s.LineStart, &s.StepKind, &s.Detail); sErr != nil {
				return sErr
			}
			f.TaintPaths = append(f.TaintPaths, s)
		}
		return rows.Err()
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "finding not found", "NOT_FOUND")
		return export.FindingData{}, false
	}

	// Attach remediation pack.
	if f.RuleID != "" && h.remediation != nil {
		f.Remediation = h.remediation.Get(f.RuleID)
	}

	// Resolve compliance controls so SARIF / Markdown exports surface
	// OWASP / PCI / NIST tags. Failures are non-fatal — a finding with
	// no resolved CWE simply ships without compliance metadata.
	if orgID, perr := uuid.Parse(user.OrgID); perr == nil {
		f.ControlRefs = resolveControlRefsForFinding(r.Context(), h.pool, orgID, f.Remediation)
	}

	return f, true
}

// cweIDsFromRemediation returns the integer CWE ids referenced in a
// remediation pack (its References slice carries titles like "CWE-79").
// Returns nil when the pack is nil or has no CWE entries.
func cweIDsFromRemediation(pack *remediation.Pack) []int {
	if pack == nil {
		return nil
	}
	var out []int
	for _, ref := range pack.References {
		title := strings.TrimSpace(ref.Title)
		if !strings.HasPrefix(title, "CWE-") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(title, "CWE-"))
		if err != nil || n <= 0 {
			continue
		}
		out = append(out, n)
	}
	return out
}

// resolveControlRefsForFinding walks the pack's CWE references,
// resolves each via compliance.ResolveControls, and returns a deduped
// deterministic slice for the exporter. Resolution failures are
// silent — a missing built-in catalog should not break the export.
func resolveControlRefsForFinding(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, pack *remediation.Pack) []export.ControlRef {
	cwes := cweIDsFromRemediation(pack)
	if len(cwes) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []export.ControlRef
	for _, cwe := range cwes {
		refs, err := compliance.ResolveControls(ctx, pool, orgID, cwe)
		if err != nil {
			continue
		}
		for _, r := range refs {
			key := r.CatalogCode + "/" + r.ControlID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, export.ControlRef{
				CatalogCode: r.CatalogCode,
				CatalogName: r.CatalogName,
				ControlID:   r.ControlID,
				Title:       r.Title,
				Confidence:  r.Confidence,
			})
		}
	}
	return out
}

func (h *Handlers) loadScanForExport(w http.ResponseWriter, r *http.Request) (export.ScanData, bool) {
	user := requireAuth(w, r)
	if user == nil {
		return export.ScanData{}, false
	}
	if !policy.Evaluate(user.Role, "scans.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return export.ScanData{}, false
	}

	id := r.PathValue("id")
	var d export.ScanData
	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		var startedAt, finishedAt *time.Time
		qErr := conn.QueryRow(ctx,
			`SELECT sj.id, sj.scan_type, sj.scan_profile, sj.status,
			        COALESCE(p.display_name, p.name, ''),
			        COALESCE(t.label, t.base_url, ''),
			        COALESCE(sa.name, ''),
			        sj.created_at, sj.started_at, sj.completed_at
			   FROM scans.scan_jobs sj
			   LEFT JOIN core.projects p ON p.id = sj.project_id
			   LEFT JOIN core.scan_targets t ON t.id = sj.scan_target_id
			   LEFT JOIN scans.source_artifacts sa ON sa.id::text = (sj.source_ref->>'artifact_id')
			  WHERE sj.id = $1`, id,
		).Scan(&d.ScanID, &d.ScanType, &d.ScanProfile, &d.Status,
			&d.ProjectName, &d.TargetLabel, &d.ArtifactName,
			&d.CreatedAt, &startedAt, &finishedAt)
		if qErr != nil {
			return qErr
		}
		d.StartedAt = startedAt
		d.FinishedAt = finishedAt

		// Load findings for this scan.
		rows, fErr := conn.Query(ctx,
			`SELECT id, title, severity, status, finding_type, COALESCE(rule_id,''),
			        COALESCE(description,''), COALESCE(file_path,''), line_start,
			        COALESCE(url,''), COALESCE(http_method,''), COALESCE(parameter,''),
			        created_at
			 FROM findings.findings WHERE scan_job_id = $1
			 ORDER BY CASE severity
			   WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
			   WHEN 'low' THEN 4 ELSE 5 END, created_at`, id)
		if fErr != nil {
			return fErr
		}
		defer rows.Close()
		for rows.Next() {
			var f export.FindingData
			var lineStart *int
			if sErr := rows.Scan(&f.ID, &f.Title, &f.Severity, &f.Status, &f.FindingType,
				&f.RuleID, &f.Description, &f.FilePath, &lineStart,
				&f.URL, &f.Method, &f.Parameter, &f.CreatedAt); sErr != nil {
				return sErr
			}
			if lineStart != nil {
				f.LineStart = *lineStart
			}
			if f.RuleID != "" && h.remediation != nil {
				f.Remediation = h.remediation.Get(f.RuleID)
			}
			if orgID, perr := uuid.Parse(user.OrgID); perr == nil {
				f.ControlRefs = resolveControlRefsForFinding(ctx, h.pool, orgID, f.Remediation)
			}
			d.Findings = append(d.Findings, f)
		}
		return rows.Err()
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found", "NOT_FOUND")
		return export.ScanData{}, false
	}
	return d, true
}

func safeFilenameSlug(title string) string {
	s := strings.ToLower(title)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}
