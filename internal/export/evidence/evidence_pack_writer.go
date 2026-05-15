// evidence_pack_writer.go — production loader. Talks to Postgres to populate
// a PackData struct, then delegates to BuildPackFromData.
//
// Split out so unit tests can target BuildPackFromData without a database.

package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/compliance"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

// BuildInput is the production entry point arguments. The pgxpool plus
// scope is enough to materialise the entire pack; org_id is the RLS
// boundary.
type BuildInput struct {
	DB      *pgxpool.Pool
	OrgID   uuid.UUID
	BuiltBy uuid.UUID
	Scope   Scope
	Format  string  // "zip_json" or "json" (currently both produce zip_json)
	Writer  io.Writer
}

// BuildPack is the production code path. It loads risks, findings, controls,
// timeline events, audit log, approval decisions and policy snapshots from
// Postgres (RLS-scoped to OrgID), then calls BuildPackFromData.
func BuildPack(ctx context.Context, in BuildInput) (BuildMeta, error) {
	if in.DB == nil {
		return BuildMeta{}, fmt.Errorf("BuildPack: DB is required")
	}
	if in.Writer == nil {
		return BuildMeta{}, fmt.Errorf("BuildPack: Writer is required")
	}
	if in.OrgID == uuid.Nil {
		return BuildMeta{}, fmt.Errorf("BuildPack: OrgID is required")
	}

	data := PackData{
		OrgID:   in.OrgID,
		Scope:   in.Scope,
		Format:  in.Format,
		BuiltAt: time.Now().UTC(),
		BuiltBy: in.BuiltBy,
	}

	// We pass an empty user id to WithRLS so SET LOCAL app.current_user_id
	// is set to the empty string — that's fine: the pack builder is a
	// privileged worker action and the org filter alone is enough.
	err := db.WithRLS(ctx, in.DB, in.BuiltBy.String(), in.OrgID.String(), func(ctx context.Context, conn *pgxpool.Conn) error {
		risks, err := loadRisks(ctx, conn, in.OrgID, in.Scope)
		if err != nil {
			return fmt.Errorf("load risks: %w", err)
		}
		data.Risks = risks

		findings, err := loadFindings(ctx, conn, in.OrgID, in.Scope, risks)
		if err != nil {
			return fmt.Errorf("load findings: %w", err)
		}
		data.Findings = findings

		// Controls are a union over every CWE referenced by the risks
		// in scope. We resolve via compliance.ResolveControls so the
		// org's tenant-overridden mappings are honoured.
		controls, err := loadControlRefs(ctx, in.DB, in.OrgID, risks, findings)
		if err != nil {
			return fmt.Errorf("load controls: %w", err)
		}
		data.Controls = controls

		timeline, err := loadTimeline(ctx, conn, in.OrgID, risks, findings)
		if err != nil {
			return fmt.Errorf("load timeline: %w", err)
		}
		data.TimelineEvents = timeline

		audit, err := loadAuditEntries(ctx, conn, in.OrgID, risks, findings)
		if err != nil {
			return fmt.Errorf("load audit entries: %w", err)
		}
		data.AuditEntries = audit

		approvals, err := loadApprovalDecisions(ctx, conn, in.OrgID, findings)
		if err != nil {
			return fmt.Errorf("load approval decisions: %w", err)
		}
		data.ApprovalDecisions = approvals

		slaPol, orgSet, err := loadPolicySnapshots(ctx, conn, in.OrgID)
		if err != nil {
			return fmt.Errorf("load policy snapshots: %w", err)
		}
		data.SLAPolicy = slaPol
		data.OrgSettings = orgSet

		return nil
	})
	if err != nil {
		return BuildMeta{}, err
	}

	return BuildPackFromData(ctx, data, in.Writer)
}

// loadRisks pulls rows from risk.clusters filtered by Scope. RiskIDs takes
// precedence; falling back to ProjectID when set; otherwise everything in
// the org (capped via 1k row hard limit).
func loadRisks(ctx context.Context, conn *pgxpool.Conn, orgID uuid.UUID, scope Scope) ([]Risk, error) {
	q := `
		SELECT c.id, c.project_id, c.title, c.vuln_class, c.severity, c.status,
		       c.risk_score, COALESCE(c.cwe_id, 0), COALESCE(c.owasp_category, ''),
		       c.first_seen_at, c.last_seen_at, c.resolved_at
		  FROM risk.clusters c
		  JOIN core.projects p ON p.id = c.project_id
		 WHERE p.org_id = $1`
	args := []any{orgID}

	switch {
	case len(scope.RiskIDs) > 0:
		q += ` AND c.id = ANY($2::uuid[])`
		args = append(args, scope.RiskIDs)
	case scope.ProjectID != nil:
		q += ` AND c.project_id = $2`
		args = append(args, *scope.ProjectID)
	}
	q += ` ORDER BY c.first_seen_at LIMIT 1000`

	rows, err := conn.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Risk
	for rows.Next() {
		var r Risk
		var resolvedAt *time.Time
		if err := rows.Scan(
			&r.ID, &r.ProjectID, &r.Title, &r.VulnClass, &r.Severity, &r.Status,
			&r.RiskScore, &r.CWE, &r.OWASPCategory,
			&r.FirstSeenAt, &r.LastSeenAt, &resolvedAt,
		); err != nil {
			return nil, err
		}
		if resolvedAt != nil {
			r.ResolvedAt = resolvedAt
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadFindings pulls findings.findings rows for the risks in scope (joined
// via risk.cluster_findings) plus any extra findings selected directly by
// scope.RiskIDs (covers the case where the caller wants findings without a
// cluster join).
func loadFindings(ctx context.Context, conn *pgxpool.Conn, orgID uuid.UUID, scope Scope, risks []Risk) ([]Finding, error) {
	if len(risks) == 0 && scope.ProjectID == nil {
		return nil, nil
	}
	riskIDs := make([]uuid.UUID, 0, len(risks))
	for _, r := range risks {
		riskIDs = append(riskIDs, r.ID)
	}

	var (
		q    string
		args []any
	)
	switch {
	case len(riskIDs) > 0:
		q = `
		SELECT DISTINCT f.id, cf.cluster_id, f.title, f.severity, f.status,
		       f.finding_type, COALESCE(f.rule_id, ''), COALESCE(f.description, ''),
		       COALESCE(f.file_path, ''), COALESCE(f.line_start, 0),
		       COALESCE(f.url, ''), COALESCE(f.http_method, ''), COALESCE(f.parameter, ''),
		       f.created_at
		  FROM findings.findings f
		  JOIN risk.cluster_findings cf ON cf.finding_id = f.id
		 WHERE f.org_id = $1 AND cf.cluster_id = ANY($2::uuid[])
		 ORDER BY f.created_at LIMIT 5000`
		args = []any{orgID, riskIDs}
	case scope.ProjectID != nil:
		q = `
		SELECT f.id, '00000000-0000-0000-0000-000000000000'::uuid AS cluster_id, f.title, f.severity, f.status,
		       f.finding_type, COALESCE(f.rule_id, ''), COALESCE(f.description, ''),
		       COALESCE(f.file_path, ''), COALESCE(f.line_start, 0),
		       COALESCE(f.url, ''), COALESCE(f.http_method, ''), COALESCE(f.parameter, ''),
		       f.created_at
		  FROM findings.findings f
		 WHERE f.org_id = $1 AND f.project_id = $2
		 ORDER BY f.created_at LIMIT 5000`
		args = []any{orgID, *scope.ProjectID}
	default:
		return nil, nil
	}

	rows, err := conn.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var f Finding
		var clusterID uuid.UUID
		if err := rows.Scan(
			&f.ID, &clusterID, &f.Title, &f.Severity, &f.Status,
			&f.FindingType, &f.RuleID, &f.Description,
			&f.FilePath, &f.LineStart,
			&f.URL, &f.HTTPMethod, &f.Parameter,
			&f.CreatedAt,
		); err != nil {
			return nil, err
		}
		if clusterID != uuid.Nil {
			f.RiskID = clusterID
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// loadControlRefs walks every CWE referenced by the risks/findings, resolves
// each via compliance.ResolveControls (which respects org tenant overrides
// and built-in catalogs alike), then deduplicates.
func loadControlRefs(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, risks []Risk, findings []Finding) ([]ControlRef, error) {
	cwes := map[int]struct{}{}
	for _, r := range risks {
		if r.CWE > 0 {
			cwes[r.CWE] = struct{}{}
		}
	}
	// Findings carry rule_ids; cluster.cwe_id covers the most common case.
	// We don't currently parse CWEs out of finding remediation packs here
	// because the cluster join already tags every finding with its risk's
	// CWE. Future enhancement: walk f.RuleID through the remediation
	// registry for findings that aren't in any cluster.

	if len(cwes) == 0 {
		return nil, nil
	}

	seen := map[string]bool{}
	var out []ControlRef
	for cwe := range cwes {
		refs, err := compliance.ResolveControls(ctx, pool, orgID, cwe)
		if err != nil {
			// Resolution is best-effort — a missing catalog row should
			// not break the export.
			continue
		}
		for _, r := range refs {
			key := r.CatalogCode + "/" + r.ControlID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ControlRef{
				CatalogCode: r.CatalogCode,
				CatalogName: r.CatalogName,
				ControlID:   r.ControlID,
				Title:       r.Title,
				Confidence:  r.Confidence,
			})
		}
	}
	return out, nil
}

// loadTimeline merges first-seen timestamps, finding transitions, approval
// decisions, and SLA breaches into one chronologically-ordered slice.
func loadTimeline(ctx context.Context, conn *pgxpool.Conn, orgID uuid.UUID, risks []Risk, findings []Finding) ([]TimelineEvent, error) {
	out := make([]TimelineEvent, 0, len(findings)+len(risks))

	for _, r := range risks {
		out = append(out, TimelineEvent{
			At:           r.FirstSeenAt,
			Kind:         "risk.first_seen",
			ResourceType: "risk",
			ResourceID:   r.ID.String(),
			Detail:       fmt.Sprintf("severity=%s class=%s", r.Severity, r.VulnClass),
		})
		if r.ResolvedAt != nil {
			out = append(out, TimelineEvent{
				At:           *r.ResolvedAt,
				Kind:         "risk.resolved",
				ResourceType: "risk",
				ResourceID:   r.ID.String(),
			})
		}
	}
	for _, f := range findings {
		out = append(out, TimelineEvent{
			At:           f.CreatedAt,
			Kind:         "finding.first_seen",
			ResourceType: "finding",
			ResourceID:   f.ID.String(),
			Detail:       fmt.Sprintf("severity=%s status=%s", f.Severity, f.Status),
		})
	}

	// Pull governance.finding_transitions for any finding in scope.
	if len(findings) > 0 {
		ids := make([]uuid.UUID, len(findings))
		for i := range findings {
			ids[i] = findings[i].ID
		}
		rows, err := conn.Query(ctx, `
			SELECT finding_id, status_from, status_to, transitioned_at, COALESCE(reason, '')
			  FROM governance.finding_transitions
			 WHERE org_id = $1 AND finding_id = ANY($2::uuid[])
			 ORDER BY transitioned_at`,
			orgID, ids)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var fid uuid.UUID
				var from, to, reason string
				var at time.Time
				if scanErr := rows.Scan(&fid, &from, &to, &at, &reason); scanErr != nil {
					continue
				}
				detail := from + " -> " + to
				if reason != "" {
					detail += " (" + reason + ")"
				}
				out = append(out, TimelineEvent{
					At:           at,
					Kind:         "finding.transition",
					ResourceType: "finding",
					ResourceID:   fid.String(),
					Detail:       detail,
				})
			}
		}
	}

	// SLA violations.
	if len(findings) > 0 {
		ids := make([]uuid.UUID, len(findings))
		for i := range findings {
			ids[i] = findings[i].ID
		}
		rows, err := conn.Query(ctx, `
			SELECT finding_id, severity, deadline_at, violated_at
			  FROM governance.sla_violations
			 WHERE finding_id = ANY($1::uuid[])
			 ORDER BY violated_at`,
			ids)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var fid uuid.UUID
				var sev string
				var deadline, violated time.Time
				if scanErr := rows.Scan(&fid, &sev, &deadline, &violated); scanErr != nil {
					continue
				}
				out = append(out, TimelineEvent{
					At:           violated,
					Kind:         "sla.violated",
					ResourceType: "finding",
					ResourceID:   fid.String(),
					Detail:       fmt.Sprintf("severity=%s deadline=%s", sev, deadline.Format(time.RFC3339)),
				})
			}
		}
	}

	return out, nil
}

// loadAuditEntries snapshots audit.audit_log rows whose (resource_type,
// resource_id) pair touches one of the in-scope risks or findings.
func loadAuditEntries(ctx context.Context, conn *pgxpool.Conn, orgID uuid.UUID, risks []Risk, findings []Finding) ([]AuditEntry, error) {
	if len(risks) == 0 && len(findings) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(risks)+len(findings))
	for _, r := range risks {
		ids = append(ids, r.ID.String())
	}
	for _, f := range findings {
		ids = append(ids, f.ID.String())
	}

	rows, err := conn.Query(ctx, `
		SELECT timestamp, action, actor_type, actor_id, resource_type, resource_id, result, details
		  FROM audit.audit_log
		 WHERE org_id = $1 AND resource_id = ANY($2::text[])
		 ORDER BY timestamp
		 LIMIT 10000`,
		orgID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var detailsRaw []byte
		if err := rows.Scan(&e.Timestamp, &e.Action, &e.ActorType, &e.ActorID, &e.ResourceType, &e.ResourceID, &e.Result, &detailsRaw); err != nil {
			return nil, err
		}
		if len(detailsRaw) > 0 {
			_ = json.Unmarshal(detailsRaw, &e.Details)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// loadApprovalDecisions returns governance.approval_decisions rows that
// pertain to any of the findings in scope. Joined via approval_requests so
// we can filter on resource_id.
func loadApprovalDecisions(ctx context.Context, conn *pgxpool.Conn, orgID uuid.UUID, findings []Finding) ([]ApprovalDecision, error) {
	if len(findings) == 0 {
		return nil, nil
	}
	resourceIDs := make([]string, len(findings))
	for i := range findings {
		resourceIDs[i] = findings[i].ID.String()
	}
	rows, err := conn.Query(ctx, `
		SELECT d.approval_request_id, d.decision, d.decided_by, d.decided_at, COALESCE(d.reason, '')
		  FROM governance.approval_decisions d
		  JOIN governance.approval_requests ar ON ar.id = d.approval_request_id
		 WHERE ar.org_id = $1 AND ar.resource_id = ANY($2::text[])
		 ORDER BY d.decided_at`,
		orgID, resourceIDs)
	if err != nil {
		// Many existing test orgs do not have approval rows — silently
		// return empty rather than fail the whole pack build.
		if isMissingRelationErr(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []ApprovalDecision
	for rows.Next() {
		var d ApprovalDecision
		if err := rows.Scan(&d.ApprovalID, &d.Decision, &d.DecidedBy, &d.DecidedAt, &d.Reason); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// loadPolicySnapshots reads the in-force SLA policy and org settings
// columns at export time. Both are returned as raw maps so we don't tie
// the bundle schema to controlplane Go structs.
func loadPolicySnapshots(ctx context.Context, conn *pgxpool.Conn, orgID uuid.UUID) (sla map[string]any, orgSet map[string]any, err error) {
	// Org-level SLA defaults live in governance.org_settings.sla_days.
	var slaRaw, settingsRaw []byte
	scanErr := conn.QueryRow(ctx, `
		SELECT COALESCE(sla_days, '{}'::jsonb), to_jsonb(o.*) - 'sla_days'
		  FROM governance.org_settings o
		 WHERE org_id = $1`, orgID).Scan(&slaRaw, &settingsRaw)
	if scanErr != nil {
		// Missing row is acceptable — return empty maps.
		return map[string]any{}, map[string]any{}, nil //nolint:nilerr
	}

	if len(slaRaw) > 0 {
		_ = json.Unmarshal(slaRaw, &sla)
	}
	if sla == nil {
		sla = map[string]any{}
	}
	if len(settingsRaw) > 0 {
		_ = json.Unmarshal(settingsRaw, &orgSet)
	}
	if orgSet == nil {
		orgSet = map[string]any{}
	}
	return sla, orgSet, nil
}

// isMissingRelationErr is a defensive helper for environments where the
// approval_decisions table predates the row-level join we use above. The
// retention worker test suite seeds orgs without governance tables.
func isMissingRelationErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "does not exist") || strings.Contains(msg, "undefined_table")
}
