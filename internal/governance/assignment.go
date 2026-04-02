package governance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

// AssignFinding creates a new finding assignment and updates the finding's
// assigned_to field.
func AssignFinding(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, assignment *FindingAssignment) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}
	if assignment == nil {
		return errors.New("governance: assignment is nil")
	}

	if assignment.ID == "" {
		assignment.ID = uuid.New().String()
	}
	assignment.OrgID = orgID
	assignment.AssignedBy = userID
	assignment.Status = "active"
	assignment.CreatedAt = time.Now()
	assignment.UpdatedAt = assignment.CreatedAt

	return db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		_, err := conn.Exec(ctx, `
			INSERT INTO governance.finding_assignments (
				id, finding_id, org_id, team_id, assigned_to, assigned_by,
				due_at, status, note, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			assignment.ID, assignment.FindingID, assignment.OrgID, assignment.TeamID,
			assignment.AssignedTo, assignment.AssignedBy, assignment.DueAt,
			assignment.Status, assignment.Note, assignment.CreatedAt, assignment.UpdatedAt,
		)
		if err != nil {
			return err
		}

		_, err = conn.Exec(ctx, `
			UPDATE findings.findings
			   SET assigned_to = $1, updated_at = now()
			 WHERE id = $2`,
			assignment.AssignedTo, assignment.FindingID,
		)
		return err
	})
}

// ReassignFinding marks the current assignment as 'reassigned', creates a new
// assignment for the new assignee, and updates the finding's assigned_to field.
func ReassignFinding(ctx context.Context, pool *pgxpool.Pool, userID, orgID, assignmentID, newAssignee string) (*FindingAssignment, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}

	var newAssignment FindingAssignment
	err := db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		// Mark old assignment as reassigned.
		now := time.Now()
		_, err := conn.Exec(ctx, `
			UPDATE governance.finding_assignments
			   SET status = 'reassigned', updated_at = $1
			 WHERE id = $2`,
			now, assignmentID,
		)
		if err != nil {
			return fmt.Errorf("update old assignment: %w", err)
		}

		// Fetch old assignment details to copy finding_id and team_id.
		var findingID, teamID string
		var dueAt *time.Time
		row := conn.QueryRow(ctx, `
			SELECT finding_id, team_id, due_at
			  FROM governance.finding_assignments
			 WHERE id = $1`, assignmentID)
		if err := row.Scan(&findingID, &teamID, &dueAt); err != nil {
			return fmt.Errorf("fetch old assignment: %w", err)
		}

		// Insert new assignment.
		newAssignment = FindingAssignment{
			ID:         uuid.New().String(),
			FindingID:  findingID,
			OrgID:      orgID,
			TeamID:     teamID,
			AssignedTo: newAssignee,
			AssignedBy: userID,
			DueAt:      dueAt,
			Status:     "active",
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		_, err = conn.Exec(ctx, `
			INSERT INTO governance.finding_assignments (
				id, finding_id, org_id, team_id, assigned_to, assigned_by,
				due_at, status, note, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			newAssignment.ID, newAssignment.FindingID, newAssignment.OrgID,
			newAssignment.TeamID, newAssignment.AssignedTo, newAssignment.AssignedBy,
			newAssignment.DueAt, newAssignment.Status, newAssignment.Note,
			newAssignment.CreatedAt, newAssignment.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("insert new assignment: %w", err)
		}

		// Update finding's assigned_to.
		_, err = conn.Exec(ctx, `
			UPDATE findings.findings
			   SET assigned_to = $1, updated_at = now()
			 WHERE id = $2`,
			newAssignee, findingID,
		)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("governance: reassign finding: %w", err)
	}
	return &newAssignment, nil
}

// CompleteFindingAssignment marks an assignment as completed.
func CompleteFindingAssignment(ctx context.Context, pool *pgxpool.Pool, userID, orgID, assignmentID string) error {
	if pool == nil {
		return errors.New("governance: pool is nil")
	}

	return db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		now := time.Now()
		_, err := conn.Exec(ctx, `
			UPDATE governance.finding_assignments
			   SET status = 'completed', completed_at = $1, updated_at = $1
			 WHERE id = $2`,
			now, assignmentID,
		)
		return err
	})
}

// ListAssignments returns paged finding assignments with optional filters for
// assignee and status.
func ListAssignments(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, assigneeFilter, statusFilter string, limit, offset int) ([]FindingAssignment, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	if limit <= 0 {
		limit = 50
	}

	var results []FindingAssignment
	err := db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		query := `
			SELECT id, finding_id, org_id, team_id, assigned_to, assigned_by,
			       due_at, status, note, created_at, updated_at, completed_at
			  FROM governance.finding_assignments
			 WHERE 1=1`
		args := []interface{}{}
		argIdx := 1

		if assigneeFilter != "" {
			query += fmt.Sprintf(" AND assigned_to = $%d", argIdx)
			args = append(args, assigneeFilter)
			argIdx++
		}
		if statusFilter != "" {
			query += fmt.Sprintf(" AND status = $%d", argIdx)
			args = append(args, statusFilter)
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
			var a FindingAssignment
			if scanErr := rows.Scan(
				&a.ID, &a.FindingID, &a.OrgID, &a.TeamID, &a.AssignedTo, &a.AssignedBy,
				&a.DueAt, &a.Status, &a.Note, &a.CreatedAt, &a.UpdatedAt, &a.CompletedAt,
			); scanErr != nil {
				return scanErr
			}
			results = append(results, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("governance: list assignments: %w", err)
	}
	return results, nil
}
