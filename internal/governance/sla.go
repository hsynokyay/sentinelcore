package governance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CalculateSLADeadline returns the SLA deadline for a finding based on its
// severity and the organisation's settings. If the severity is not found in
// settings, a default of 90 days is used.
func CalculateSLADeadline(createdAt time.Time, severity string, settings *OrgSettings) time.Time {
	days := 90 // default when severity not found
	if settings != nil && settings.DefaultFindingSLADays != nil {
		if d, ok := settings.DefaultFindingSLADays[severity]; ok {
			days = d
		}
	}
	return createdAt.Add(time.Duration(days) * 24 * time.Hour)
}

// CheckSLAViolations finds findings that have breached their SLA deadline but
// do not yet have a violation record. This operates across all orgs (no RLS)
// and is intended for the retention worker.
func CheckSLAViolations(ctx context.Context, pool *pgxpool.Pool, now time.Time) ([]SLAViolation, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	rows, err := conn.Query(ctx, `
		SELECT f.id, f.org_id, f.severity, f.sla_deadline
		  FROM findings.findings f
		 WHERE f.sla_deadline < $1
		   AND f.status NOT IN ('resolved', 'false_positive', 'accepted_risk')
		   AND NOT EXISTS (
		       SELECT 1 FROM governance.sla_violations v
		        WHERE v.finding_id = f.id
		   )`, now)
	if err != nil {
		return nil, fmt.Errorf("governance: check sla violations: %w", err)
	}
	defer rows.Close()

	var violations []SLAViolation
	for rows.Next() {
		var findingID, orgID, severity string
		var deadline time.Time
		if scanErr := rows.Scan(&findingID, &orgID, &severity, &deadline); scanErr != nil {
			return nil, fmt.Errorf("governance: scan sla violation: %w", scanErr)
		}
		violations = append(violations, SLAViolation{
			ID:         uuid.New().String(),
			FindingID:  findingID,
			OrgID:      orgID,
			Severity:   severity,
			DeadlineAt: deadline,
			ViolatedAt: now,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("governance: check sla violations rows: %w", err)
	}
	return violations, nil
}

// RecordSLAViolation inserts a new SLA violation record.
func RecordSLAViolation(ctx context.Context, pool *pgxpool.Pool, v *SLAViolation) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	if v == nil {
		return errors.New("governance: sla violation is nil")
	}

	if v.ID == "" {
		v.ID = uuid.New().String()
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, `
		INSERT INTO governance.sla_violations (
			id, finding_id, org_id, severity, sla_days,
			deadline_at, violated_at, resolved_at, escalated
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		v.ID, v.FindingID, v.OrgID, v.Severity, v.SLADays,
		v.DeadlineAt, v.ViolatedAt, v.ResolvedAt, v.Escalated,
	)
	if err != nil {
		return fmt.Errorf("governance: record sla violation: %w", err)
	}
	return nil
}

// CheckSLAWarnings returns finding IDs whose SLA deadline falls between now
// and now + 7 days and that do not already have a violation record. This is
// used by the retention worker to send early warnings before a breach occurs.
// Cross-org (no RLS).
func CheckSLAWarnings(ctx context.Context, pool *pgxpool.Pool, now time.Time) ([]string, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	rows, err := conn.Query(ctx, `
		SELECT f.id
		  FROM findings.findings f
		 WHERE f.sla_deadline BETWEEN $1 AND $1 + interval '7 days'
		   AND f.status NOT IN ('resolved', 'false_positive', 'accepted_risk')
		   AND NOT EXISTS (
		       SELECT 1 FROM governance.sla_violations v
		        WHERE v.finding_id = f.id
		   )`, now)
	if err != nil {
		return nil, fmt.Errorf("governance: check sla warnings: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			return nil, fmt.Errorf("governance: scan sla warning: %w", scanErr)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("governance: check sla warnings rows: %w", err)
	}
	return ids, nil
}
