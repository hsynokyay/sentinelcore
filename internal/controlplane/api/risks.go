package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

// ListRisks handles GET /api/v1/risks?project_id=...&status=active&severity=...&vuln_class=...&limit=50&offset=0
func (h *Handlers) ListRisks(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()

	projectID := q.Get("project_id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required", "BAD_REQUEST")
		return
	}

	status := q.Get("status")
	if status == "" {
		status = "active"
	}

	limit := 50
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 200 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	// Build the WHERE clause with positional args.
	args := []any{projectID}
	where := "project_id = $1"
	if status != "all" {
		args = append(args, status)
		where += " AND status = $" + strconv.Itoa(len(args))
	}
	if sev := q.Get("severity"); sev != "" {
		args = append(args, sev)
		where += " AND severity = $" + strconv.Itoa(len(args))
	}
	if vc := q.Get("vuln_class"); vc != "" {
		args = append(args, vc)
		where += " AND vuln_class = $" + strconv.Itoa(len(args))
	}
	args = append(args, limit, offset)
	limitPos := strconv.Itoa(len(args) - 1)
	offsetPos := strconv.Itoa(len(args))

	query := `
		SELECT id, title, vuln_class, COALESCE(cwe_id, 0), severity, risk_score, exposure,
		       status, finding_count, surface_count, first_seen_at, last_seen_at
		FROM risk.clusters
		WHERE ` + where + `
		ORDER BY risk_score DESC, last_seen_at DESC
		LIMIT $` + limitPos + ` OFFSET $` + offsetPos

	type risksRow struct {
		ID           string           `json:"id"`
		Title        string           `json:"title"`
		VulnClass    string           `json:"vuln_class"`
		CWEID        int              `json:"cwe_id"`
		Severity     string           `json:"severity"`
		RiskScore    int              `json:"risk_score"`
		Exposure     string           `json:"exposure"`
		Status       string           `json:"status"`
		FindingCount int              `json:"finding_count"`
		SurfaceCount int              `json:"surface_count"`
		FirstSeenAt  time.Time        `json:"first_seen_at"`
		LastSeenAt   time.Time        `json:"last_seen_at"`
		TopReasons   []map[string]any `json:"top_reasons"`
	}

	items := []risksRow{}
	var total int
	err := tenant.TxUser(ctx, h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx, query, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var item risksRow
				if err := rows.Scan(
					&item.ID, &item.Title, &item.VulnClass, &item.CWEID, &item.Severity,
					&item.RiskScore, &item.Exposure, &item.Status,
					&item.FindingCount, &item.SurfaceCount, &item.FirstSeenAt, &item.LastSeenAt,
				); err != nil {
					return err
				}
				item.TopReasons = h.loadTopReasons(ctx, tx, item.ID, 2)
				items = append(items, item)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			// Count total for pagination (same filters, no limit/offset).
			countQuery := `SELECT count(*) FROM risk.clusters WHERE ` + where
			return tx.QueryRow(ctx, countQuery, args[:len(args)-2]...).Scan(&total)
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("list risks failed")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"risks":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// loadTopReasons returns up to n score evidence rows by sort_order.
// Runs inside the parent transaction so RLS context is preserved.
func (h *Handlers) loadTopReasons(ctx context.Context, tx pgx.Tx, clusterID string, n int) []map[string]any {
	rows, err := tx.Query(ctx, `
		SELECT code, label, weight
		FROM risk.cluster_evidence
		WHERE cluster_id = $1
		  AND category IN ('score_base', 'score_boost', 'score_penalty')
		ORDER BY sort_order
		LIMIT $2
	`, clusterID, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var code, label string
		var weight *int
		if err := rows.Scan(&code, &label, &weight); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"code":   code,
			"label":  label,
			"weight": weight,
		})
	}
	return out
}

// GetRisk handles GET /api/v1/risks/{id}
func (h *Handlers) GetRisk(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required", "BAD_REQUEST")
		return
	}

	type clusterDetail struct {
		ID               string           `json:"id"`
		ProjectID        string           `json:"project_id"`
		Title            string           `json:"title"`
		VulnClass        string           `json:"vuln_class"`
		CWEID            int              `json:"cwe_id"`
		OWASPCategory    string           `json:"owasp_category,omitempty"`
		FingerprintKind  string           `json:"fingerprint_kind"`
		Language         string           `json:"language,omitempty"`
		CanonicalRoute   string           `json:"canonical_route,omitempty"`
		HTTPMethod       string           `json:"http_method,omitempty"`
		CanonicalParam   string           `json:"canonical_param,omitempty"`
		FilePath         string           `json:"file_path,omitempty"`
		EnclosingMethod  string           `json:"enclosing_method,omitempty"`
		Severity         string           `json:"severity"`
		RiskScore        int              `json:"risk_score"`
		Exposure         string           `json:"exposure"`
		Status           string           `json:"status"`
		FindingCount     int              `json:"finding_count"`
		SurfaceCount     int              `json:"surface_count"`
		FirstSeenAt      time.Time        `json:"first_seen_at"`
		LastSeenAt       time.Time        `json:"last_seen_at"`
		LastRunID        *string          `json:"last_run_id,omitempty"`
		ResolvedAt       *time.Time       `json:"resolved_at,omitempty"`
		ResolutionReason string           `json:"resolution_reason,omitempty"`
		MutedUntil       *time.Time       `json:"muted_until,omitempty"`
		Evidence         []map[string]any `json:"evidence"`
		Findings         []map[string]any `json:"findings"`
		Relations        []map[string]any `json:"relations"`
	}
	var cl clusterDetail
	var owasp, lang, route, httpMethod, param, filePath, encMethod, resolutionReason *string

	err := tenant.TxUser(ctx, h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `
				SELECT id, project_id, title, vuln_class, COALESCE(cwe_id, 0),
				       owasp_category, fingerprint_kind, language,
				       canonical_route, http_method, canonical_param,
				       file_path, enclosing_method,
				       severity, risk_score, exposure, status,
				       finding_count, surface_count, first_seen_at, last_seen_at,
				       last_run_id::text, resolved_at, resolution_reason, muted_until
				FROM risk.clusters
				WHERE id = $1
			`, id).Scan(
				&cl.ID, &cl.ProjectID, &cl.Title, &cl.VulnClass, &cl.CWEID,
				&owasp, &cl.FingerprintKind, &lang,
				&route, &httpMethod, &param,
				&filePath, &encMethod,
				&cl.Severity, &cl.RiskScore, &cl.Exposure, &cl.Status,
				&cl.FindingCount, &cl.SurfaceCount, &cl.FirstSeenAt, &cl.LastSeenAt,
				&cl.LastRunID, &cl.ResolvedAt, &resolutionReason, &cl.MutedUntil,
			); err != nil {
				return err
			}
			cl.Evidence = h.loadEvidence(ctx, tx, id)
			cl.Findings = h.loadClusterFindings(ctx, tx, id)
			cl.Relations = h.loadClusterRelations(ctx, tx, id)
			return nil
		})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "risk not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("get risk query failed")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	cl.OWASPCategory = derefString(owasp)
	cl.Language = derefString(lang)
	cl.CanonicalRoute = derefString(route)
	cl.HTTPMethod = derefString(httpMethod)
	cl.CanonicalParam = derefString(param)
	cl.FilePath = derefString(filePath)
	cl.EnclosingMethod = derefString(encMethod)
	cl.ResolutionReason = derefString(resolutionReason)

	writeJSON(w, http.StatusOK, map[string]any{"risk": cl})
}

func (h *Handlers) loadEvidence(ctx context.Context, tx pgx.Tx, clusterID string) []map[string]any {
	rows, err := tx.Query(ctx, `
		SELECT category, code, label, weight, ref_type, ref_id, sort_order
		FROM risk.cluster_evidence
		WHERE cluster_id = $1
		ORDER BY sort_order
	`, clusterID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var category, code, label string
		var weight *int
		var refType, refID *string
		var sortOrder int
		if err := rows.Scan(&category, &code, &label, &weight, &refType, &refID, &sortOrder); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"category":   category,
			"code":       code,
			"label":      label,
			"weight":     weight,
			"ref_type":   derefString(refType),
			"ref_id":     derefString(refID),
			"sort_order": sortOrder,
		})
	}
	return out
}

func (h *Handlers) loadClusterFindings(ctx context.Context, tx pgx.Tx, clusterID string) []map[string]any {
	rows, err := tx.Query(ctx, `
		SELECT f.id::text, cf.role, f.title, f.severity,
		       f.file_path, f.url, f.line_start
		FROM risk.cluster_findings cf
		JOIN findings.findings f ON f.id = cf.finding_id
		WHERE cf.cluster_id = $1
		ORDER BY cf.added_at
	`, clusterID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, role, title, severity string
		var filePath, url *string
		var lineStart *int
		if err := rows.Scan(&id, &role, &title, &severity, &filePath, &url, &lineStart); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id":         id,
			"role":       role,
			"title":      title,
			"severity":   severity,
			"file_path":  derefString(filePath),
			"url":        derefString(url),
			"line_start": lineStart,
		})
	}
	return out
}

func (h *Handlers) loadClusterRelations(ctx context.Context, tx pgx.Tx, clusterID string) []map[string]any {
	rows, err := tx.Query(ctx, `
		SELECT rel.id::text,
		       CASE WHEN rel.source_cluster_id = $1 THEN rel.target_cluster_id ELSE rel.source_cluster_id END AS other_id,
		       rel.relation_type, rel.confidence, rel.rationale,
		       other.title
		FROM risk.cluster_relations rel
		JOIN risk.clusters other
		  ON other.id = CASE WHEN rel.source_cluster_id = $1 THEN rel.target_cluster_id ELSE rel.source_cluster_id END
		WHERE rel.source_cluster_id = $1 OR rel.target_cluster_id = $1
		ORDER BY rel.confidence DESC
	`, clusterID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, otherID, relType, rationale, otherTitle string
		var confidence float64
		if err := rows.Scan(&id, &otherID, &relType, &confidence, &rationale, &otherTitle); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id":                    id,
			"related_cluster_id":    otherID,
			"relation_type":         relType,
			"confidence":            confidence,
			"rationale":             rationale,
			"related_cluster_title": otherTitle,
		})
	}
	return out
}

// ResolveRisk handles POST /api/v1/risks/{id}/resolve
func (h *Handlers) ResolveRisk(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required", "BAD_REQUEST")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &body)

	var rowsAffected int64
	err := tenant.TxUser(ctx, h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `
				UPDATE risk.clusters
				SET status = 'user_resolved',
				    resolved_at = now(),
				    resolved_by = $2,
				    resolution_reason = NULLIF($3, '')
				WHERE id = $1
			`, id, user.UserID, body.Reason)
			if err != nil {
				return err
			}
			rowsAffected = tag.RowsAffected()
			return nil
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("resolve risk failed")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	if rowsAffected == 0 {
		writeError(w, http.StatusNotFound, "risk not found", "NOT_FOUND")
		return
	}

	// Audit: risk.resolved feeds audit.risk_events via the projector.
	// Note: project-level resolution uses resource_type=risk so the
	// read endpoint shows the cluster id as the targeted resource.
	h.emitRisk(ctx, user, audit.RiskResolved, id, map[string]any{
		"risk_id": id,
		"note":    body.Reason,
	})

	writeJSON(w, http.StatusOK, map[string]any{"status": "user_resolved"})
}

// ReopenRisk handles POST /api/v1/risks/{id}/reopen
func (h *Handlers) ReopenRisk(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required", "BAD_REQUEST")
		return
	}

	var rowsAffected int64
	err := tenant.TxUser(ctx, h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `
				UPDATE risk.clusters
				SET status = 'active',
				    resolved_at = NULL,
				    resolved_by = NULL,
				    resolution_reason = NULL,
				    muted_until = NULL,
				    missing_run_count = 0
				WHERE id = $1
			`, id)
			if err != nil {
				return err
			}
			rowsAffected = tag.RowsAffected()
			return nil
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("reopen risk failed")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	if rowsAffected == 0 {
		writeError(w, http.StatusNotFound, "risk not found", "NOT_FOUND")
		return
	}

	h.emitRisk(r.Context(), user, audit.RiskReopened, id, map[string]any{
		"risk_id": id,
	})

	writeJSON(w, http.StatusOK, map[string]any{"status": "active"})
}

// MuteRisk handles POST /api/v1/risks/{id}/mute
func (h *Handlers) MuteRisk(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required", "BAD_REQUEST")
		return
	}
	var body struct {
		Until string `json:"until"` // RFC3339
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", "BAD_REQUEST")
		return
	}
	t, err := time.Parse(time.RFC3339, body.Until)
	if err != nil {
		writeError(w, http.StatusBadRequest, "until must be RFC3339", "BAD_REQUEST")
		return
	}
	if t.Before(time.Now()) {
		writeError(w, http.StatusBadRequest, "until must be in the future", "BAD_REQUEST")
		return
	}

	var rowsAffected int64
	err = tenant.TxUser(ctx, h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `
				UPDATE risk.clusters
				SET status = 'muted', muted_until = $2
				WHERE id = $1
			`, id, t)
			if err != nil {
				return err
			}
			rowsAffected = tag.RowsAffected()
			return nil
		})
	if err != nil {
		h.logger.Error().Err(err).Msg("mute risk failed")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	if rowsAffected == 0 {
		writeError(w, http.StatusNotFound, "risk not found", "NOT_FOUND")
		return
	}

	h.emitRisk(r.Context(), user, audit.RiskMuted, id, map[string]any{
		"risk_id":     id,
		"muted_until": t.UTC().Format(time.RFC3339Nano),
	})

	writeJSON(w, http.StatusOK, map[string]any{"status": "muted", "muted_until": t})
}

// RebuildRisks handles POST /api/v1/projects/{id}/risks/rebuild
func (h *Handlers) RebuildRisks(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	projectID := r.PathValue("id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project id is required", "BAD_REQUEST")
		return
	}
	if h.riskWorker == nil {
		writeError(w, http.StatusServiceUnavailable, "risk worker not configured", "UNAVAILABLE")
		return
	}
	// Fire-and-forget: respond 202 immediately; the rebuild runs in the
	// control-plane process. This keeps parity with the debug-oriented
	// usage of this endpoint without tying the HTTP request to the full
	// transaction lifetime.
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := h.riskWorker.RebuildProjectManually(bg, projectID); err != nil {
			h.logger.Error().Err(err).Str("project_id", projectID).Msg("manual risk rebuild failed")
		}
	}()

	// correlation.rebuild.triggered is project-scoped, not per-risk — the
	// projector ignores it and it goes to audit_log only.
	h.emitProjectScope(r.Context(), user, audit.CorrelationRebuildTrigg,
		"project", projectID, nil)

	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted"})
}

// emitRisk is the common shape for a risk.* audit event. The resource_id
// matches risk_id; the projector (internal/audit/projector.go) pulls
// risk_id from details regardless — kept consistent so GET /risks/{id}/history
// can use resource_id as a secondary index.
func (h *Handlers) emitRisk(ctx context.Context, user *auth.UserContext,
	action audit.Action, riskID string, details map[string]any) {
	if h.emitter == nil {
		return
	}
	_ = h.emitter.Emit(ctx, audit.AuditEvent{
		ActorType:    "user",
		ActorID:      user.UserID,
		Action:       string(action),
		ResourceType: "risk",
		ResourceID:   riskID,
		OrgID:        user.OrgID,
		Result:       audit.ResultSuccess,
		Details:      details,
	})
}

// emitProjectScope emits a project-level action (e.g. correlation rebuild).
// No risk_events projection — projector ignores non-risk.* actions.
func (h *Handlers) emitProjectScope(ctx context.Context, user *auth.UserContext,
	action audit.Action, resourceType, resourceID string, details map[string]any) {
	if h.emitter == nil {
		return
	}
	_ = h.emitter.Emit(ctx, audit.AuditEvent{
		ActorType:    "user",
		ActorID:      user.UserID,
		Action:       string(action),
		ResourceType: resourceType,
		ResourceID:   resourceID,
		OrgID:        user.OrgID,
		ProjectID:    resourceID,
		Result:       audit.ResultSuccess,
		Details:      details,
	})
}

// derefString safely dereferences a nullable string.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
