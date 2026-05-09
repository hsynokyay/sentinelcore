package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SLADashboard summarises SLA posture for one org.
type SLADashboard struct {
	CountsByStatus   map[string]int  `json:"counts_by_status"`
	CountsBySeverity map[string]int  `json:"counts_by_severity"`
	TopBreaches      []BreachSummary `json:"top_breaches"`
	Trend            []TrendBucket   `json:"trend"`
}

// BreachSummary is one row in the dashboard's breach table.
type BreachSummary struct {
	FindingID    string    `json:"finding_id"`
	ProjectID    string    `json:"project_id"`
	Severity     string    `json:"severity"`
	Status       string    `json:"status"`
	DeadlineAt   time.Time `json:"deadline_at"`
	OverdueHours int       `json:"overdue_hours"`
	Title        string    `json:"title"`
}

// TrendBucket reports a daily breach count over a rolling window.
type TrendBucket struct {
	Day      time.Time `json:"day"`
	Breaches int       `json:"breaches"`
}

// SLAViolationSummary is a row used by the dashboard's "Violations" list.
type SLAViolationSummary struct {
	ID           string     `json:"id"`
	FindingID    string     `json:"finding_id"`
	Severity     string     `json:"severity"`
	DeadlineAt   time.Time  `json:"deadline_at"`
	ViolatedAt   time.Time  `json:"violated_at"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	OverdueHours int        `json:"overdue_hours"`
}

// statusOpenSet enumerates finding statuses that still count toward SLA.
const statusOpenSet = `('new','triaged','in_progress','reopened')`

// GetSLADashboard returns aggregate SLA counters and the top recent breaches
// for an organisation.
//
// Status taxonomy:
//
//   - "breached"  → sla_deadline < now() and finding is still open
//   - "at_risk"   → sla_deadline within [now(), now() + warningWindow] and open
//   - "on_track"  → sla_deadline > now() + warningWindow and open
//
// Closed/resolved findings are excluded from all counts.
//
// warningWindow defaults to 7 days when zero.
func GetSLADashboard(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, warningWindow time.Duration) (*SLADashboard, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	if warningWindow <= 0 {
		warningWindow = 7 * 24 * time.Hour
	}

	now := time.Now()
	warnUntil := now.Add(warningWindow)

	dash := &SLADashboard{
		CountsByStatus:   map[string]int{"breached": 0, "at_risk": 0, "on_track": 0},
		CountsBySeverity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
	}

	// Counts by status + severity in a single pass.
	rows, err := pool.Query(ctx, `
		SELECT severity,
		       CASE
		         WHEN sla_deadline < $2 THEN 'breached'
		         WHEN sla_deadline <= $3 THEN 'at_risk'
		         ELSE 'on_track'
		       END AS sla_status,
		       count(*)::int
		  FROM findings.findings
		 WHERE org_id = $1
		   AND sla_deadline IS NOT NULL
		   AND status IN `+statusOpenSet+`
		 GROUP BY severity, sla_status
	`, orgID, now, warnUntil)
	if err != nil {
		return nil, fmt.Errorf("governance: sla counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sev, status string
		var n int
		if scanErr := rows.Scan(&sev, &status, &n); scanErr != nil {
			return nil, fmt.Errorf("governance: scan sla count: %w", scanErr)
		}
		dash.CountsByStatus[status] += n
		dash.CountsBySeverity[sev] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("governance: sla counts iter: %w", err)
	}

	// Top breaches — most overdue first, capped to 25.
	breachRows, err := pool.Query(ctx, `
		SELECT id, project_id, severity, status, sla_deadline, title
		  FROM findings.findings
		 WHERE org_id = $1
		   AND sla_deadline IS NOT NULL
		   AND sla_deadline < $2
		   AND status IN `+statusOpenSet+`
		 ORDER BY sla_deadline ASC
		 LIMIT 25
	`, orgID, now)
	if err != nil {
		return nil, fmt.Errorf("governance: top breaches: %w", err)
	}
	defer breachRows.Close()
	for breachRows.Next() {
		var b BreachSummary
		if scanErr := breachRows.Scan(&b.FindingID, &b.ProjectID, &b.Severity, &b.Status, &b.DeadlineAt, &b.Title); scanErr != nil {
			return nil, fmt.Errorf("governance: scan breach: %w", scanErr)
		}
		b.OverdueHours = int(now.Sub(b.DeadlineAt).Hours())
		dash.TopBreaches = append(dash.TopBreaches, b)
	}
	if err := breachRows.Err(); err != nil {
		return nil, fmt.Errorf("governance: top breaches iter: %w", err)
	}
	if dash.TopBreaches == nil {
		dash.TopBreaches = []BreachSummary{}
	}

	// 30-day trend, daily buckets, counted by violated_at.
	trendRows, err := pool.Query(ctx, `
		SELECT date_trunc('day', violated_at) AS day, count(*)::int
		  FROM governance.sla_violations
		 WHERE org_id = $1
		   AND violated_at >= $2
		 GROUP BY day
		 ORDER BY day ASC
	`, orgID, now.Add(-30*24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("governance: trend: %w", err)
	}
	defer trendRows.Close()
	for trendRows.Next() {
		var t TrendBucket
		if scanErr := trendRows.Scan(&t.Day, &t.Breaches); scanErr != nil {
			return nil, fmt.Errorf("governance: scan trend: %w", scanErr)
		}
		dash.Trend = append(dash.Trend, t)
	}
	if err := trendRows.Err(); err != nil {
		return nil, fmt.Errorf("governance: trend iter: %w", err)
	}
	if dash.Trend == nil {
		dash.Trend = []TrendBucket{}
	}

	return dash, nil
}

// ListSLAViolations returns recent SLA violations for an org. resolvedFilter
// values: "open" (resolved_at IS NULL), "resolved" (NOT NULL), "all".
func ListSLAViolations(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, resolvedFilter string, limit int) ([]SLAViolationSummary, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	resolvedClause := ""
	switch resolvedFilter {
	case "open", "":
		resolvedClause = "AND resolved_at IS NULL"
	case "resolved":
		resolvedClause = "AND resolved_at IS NOT NULL"
	case "all":
		resolvedClause = ""
	}

	rows, err := pool.Query(ctx, `
		SELECT id, finding_id, severity, deadline_at, violated_at, resolved_at
		  FROM governance.sla_violations
		 WHERE org_id = $1
		`+resolvedClause+`
		 ORDER BY violated_at DESC
		 LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("governance: list sla violations: %w", err)
	}
	defer rows.Close()

	now := time.Now()
	out := []SLAViolationSummary{}
	for rows.Next() {
		var v SLAViolationSummary
		if scanErr := rows.Scan(&v.ID, &v.FindingID, &v.Severity, &v.DeadlineAt, &v.ViolatedAt, &v.ResolvedAt); scanErr != nil {
			return nil, fmt.Errorf("governance: scan sla violation: %w", scanErr)
		}
		v.OverdueHours = int(now.Sub(v.DeadlineAt).Hours())
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("governance: list sla violations iter: %w", err)
	}
	return out, nil
}

// ProjectSLAPolicy is the wire shape returned by GET/PUT
// /api/v1/governance/sla/policies/{project_id}.
type ProjectSLAPolicy struct {
	ProjectID string         `json:"project_id"`
	OrgID     string         `json:"org_id"`
	SLADays   map[string]int `json:"sla_days"`
	UpdatedAt time.Time      `json:"updated_at"`
	UpdatedBy string         `json:"updated_by"`
}

// GetProjectSLAPolicy returns the per-project SLA policy if present, or
// pgx.ErrNoRows if no override row exists.
func GetProjectSLAPolicy(ctx context.Context, pool *pgxpool.Pool, projectID uuid.UUID) (*ProjectSLAPolicy, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	var p ProjectSLAPolicy
	var raw []byte
	err := pool.QueryRow(ctx, `
		SELECT project_id, org_id, sla_days, updated_at, updated_by
		  FROM governance.project_sla_policies
		 WHERE project_id = $1
	`, projectID).Scan(&p.ProjectID, &p.OrgID, &raw, &p.UpdatedAt, &p.UpdatedBy)
	if err != nil {
		return nil, err
	}
	out, decodeErr := decodeSLADays(raw)
	if decodeErr != nil {
		return nil, fmt.Errorf("governance: decode project sla_days: %w", decodeErr)
	}
	p.SLADays = out
	return &p, nil
}

// UpsertProjectSLAPolicy creates or updates a project-level SLA override.
// The map MUST contain critical/high/medium/low keys — the DB CHECK constraint
// rejects anything else.
func UpsertProjectSLAPolicy(ctx context.Context, pool *pgxpool.Pool, orgID, projectID, updatedBy uuid.UUID, slaDays map[string]int) (*ProjectSLAPolicy, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	if err := validateSLADaysMap(slaDays); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(slaDays)
	if err != nil {
		return nil, fmt.Errorf("governance: marshal sla_days: %w", err)
	}

	var p ProjectSLAPolicy
	var stored []byte
	err = pool.QueryRow(ctx, `
		INSERT INTO governance.project_sla_policies (org_id, project_id, sla_days, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (project_id) DO UPDATE
		   SET sla_days   = EXCLUDED.sla_days,
		       updated_by = EXCLUDED.updated_by,
		       updated_at = now()
		RETURNING project_id, org_id, sla_days, updated_at, updated_by
	`, orgID, projectID, raw, updatedBy).Scan(&p.ProjectID, &p.OrgID, &stored, &p.UpdatedAt, &p.UpdatedBy)
	if err != nil {
		return nil, fmt.Errorf("governance: upsert project sla policy: %w", err)
	}
	decoded, decodeErr := decodeSLADays(stored)
	if decodeErr != nil {
		return nil, fmt.Errorf("governance: decode upsert sla_days: %w", decodeErr)
	}
	p.SLADays = decoded
	return &p, nil
}

// DeleteProjectSLAPolicy removes a project-level SLA override. Returns
// pgx.ErrNoRows if no row was deleted (caller may map that to 404).
func DeleteProjectSLAPolicy(ctx context.Context, pool *pgxpool.Pool, projectID uuid.UUID) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	tag, err := pool.Exec(ctx, `
		DELETE FROM governance.project_sla_policies WHERE project_id = $1
	`, projectID)
	if err != nil {
		return fmt.Errorf("governance: delete project sla policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func validateSLADaysMap(m map[string]int) error {
	if m == nil {
		return errors.New("governance: sla_days is nil")
	}
	for _, k := range []string{"critical", "high", "medium", "low"} {
		v, ok := m[k]
		if !ok {
			return fmt.Errorf("governance: sla_days missing %q", k)
		}
		if v <= 0 {
			return fmt.Errorf("governance: sla_days[%q] must be > 0", k)
		}
	}
	return nil
}
