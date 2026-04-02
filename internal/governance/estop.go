package governance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

// ActivateEmergencyStop inserts a new active emergency stop record.
func ActivateEmergencyStop(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, stop *EmergencyStop) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	if stop == nil {
		return errors.New("governance: emergency stop is nil")
	}

	if stop.ID == "" {
		stop.ID = uuid.New().String()
	}
	stop.OrgID = orgID
	stop.ActivatedBy = userID
	stop.ActivatedAt = time.Now()
	stop.Active = true

	return db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		_, err := conn.Exec(ctx, `
			INSERT INTO governance.emergency_stops (
				id, org_id, scope, scope_id, reason,
				activated_by, activated_at, active
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			stop.ID, stop.OrgID, stop.Scope, stop.ScopeID, stop.Reason,
			stop.ActivatedBy, stop.ActivatedAt, stop.Active,
		)
		return err
	})
}

// LiftEmergencyStop deactivates an emergency stop. A four-eyes principle is
// enforced: the user who activated the stop cannot be the one to lift it.
func LiftEmergencyStop(ctx context.Context, pool *pgxpool.Pool, userID, orgID, stopID string) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}

	return db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		var activatedBy string
		row := conn.QueryRow(ctx, `
			SELECT activated_by
			  FROM governance.emergency_stops
			 WHERE id = $1`, stopID)
		if err := row.Scan(&activatedBy); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("governance: emergency stop %s not found", stopID)
			}
			return err
		}

		if activatedBy == userID {
			return errors.New("governance: the user who activated an emergency stop cannot lift it")
		}

		now := time.Now()
		_, err := conn.Exec(ctx, `
			UPDATE governance.emergency_stops
			   SET active = false,
			       deactivated_by = $1,
			       deactivated_at = $2
			 WHERE id = $3`,
			userID, now, stopID,
		)
		return err
	})
}

// IsEmergencyStopped checks whether an active emergency stop exists that
// covers the given scope. A stop with scope='all' matches everything. No RLS
// is needed because this is used by scan dispatch to check before starting.
func IsEmergencyStopped(ctx context.Context, pool *pgxpool.Pool, orgID, scope, scopeID string) (bool, error) {
	if pool == nil {
		return false, errors.New("governance: pool is nil")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("governance: acquire conn: %w", err)
	}
	defer conn.Release()

	var exists bool
	err = conn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM governance.emergency_stops
			 WHERE org_id = $1
			   AND active = true
			   AND (scope = 'all' OR (scope = $2 AND scope_id = $3))
		)`, orgID, scope, scopeID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("governance: is emergency stopped: %w", err)
	}
	return exists, nil
}

// ListActiveStops returns all active emergency stops for the organisation.
func ListActiveStops(ctx context.Context, pool *pgxpool.Pool, userID, orgID string) ([]EmergencyStop, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}

	var results []EmergencyStop
	err := db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		rows, err := conn.Query(ctx, `
			SELECT id, org_id, scope, scope_id, reason,
			       activated_by, activated_at, deactivated_by, deactivated_at, active
			  FROM governance.emergency_stops
			 WHERE active = true
			 ORDER BY activated_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var s EmergencyStop
			if scanErr := rows.Scan(
				&s.ID, &s.OrgID, &s.Scope, &s.ScopeID, &s.Reason,
				&s.ActivatedBy, &s.ActivatedAt, &s.DeactivatedBy, &s.DeactivatedAt, &s.Active,
			); scanErr != nil {
				return scanErr
			}
			results = append(results, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("governance: list active stops: %w", err)
	}
	return results, nil
}
