package governance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Decision-service errors. Callers (HTTP handlers, triage) should errors.Is
// against these for stable status-code mapping.
var (
	// ErrSelfApprovalForbidden is returned when the requester tries to
	// approve or reject their own request.
	ErrSelfApprovalForbidden = errors.New("governance: self-approval forbidden")
	// ErrDuplicateDecision is returned when the same approver records a
	// second decision on the same request.
	ErrDuplicateDecision = errors.New("governance: approver already decided")
	// ErrAlreadyDecided is returned when a request has already left the
	// 'pending' state (approved/rejected/expired/executed).
	ErrAlreadyDecided = errors.New("governance: approval request already decided")
	// ErrExpired is returned when a request's expires_at has passed.
	ErrExpired = errors.New("governance: approval request expired")
	// ErrApprovalNotFound is returned when the row does not exist.
	ErrApprovalNotFound = errors.New("governance: approval request not found")
)

// CreateApprovalReq is the input shape for CreateApprovalRequest. It is
// deliberately distinct from the persisted ApprovalRequest so the caller
// cannot smuggle in server-managed fields (id, status, current_approvals).
type CreateApprovalReq struct {
	OrgID             uuid.UUID
	TeamID            *uuid.UUID
	RequestedBy       uuid.UUID
	RequestType       string
	ResourceType      string
	ResourceID        uuid.UUID
	Reason            string
	RequiredApprovals int
	TargetTransition  string
	ProjectID         *uuid.UUID
	// ExpiresAt overrides the default 7-day expiry. Zero value uses the default.
	ExpiresAt time.Time
}

// CreateApprovalRequest inserts a new governance.approval_requests row and
// returns it. The row is created with status='pending' and current_approvals=0.
// Caller must populate RequiredApprovals (>=1, <=3 per CHECK constraint).
func CreateApprovalRequest(ctx context.Context, pool *pgxpool.Pool, in CreateApprovalReq) (*ApprovalRequest, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	if in.OrgID == uuid.Nil {
		return nil, errors.New("governance: OrgID is required")
	}
	if in.RequestedBy == uuid.Nil {
		return nil, errors.New("governance: RequestedBy is required")
	}
	if in.RequestType == "" || in.ResourceType == "" {
		return nil, errors.New("governance: RequestType and ResourceType are required")
	}
	if in.RequiredApprovals < 1 {
		in.RequiredApprovals = 1
	}
	if in.RequiredApprovals > 3 {
		return nil, fmt.Errorf("governance: RequiredApprovals must be <= 3 (got %d)", in.RequiredApprovals)
	}

	id := uuid.New()
	now := time.Now()
	expires := in.ExpiresAt
	if expires.IsZero() {
		expires = now.Add(7 * 24 * time.Hour)
	}

	var teamArg interface{}
	if in.TeamID != nil {
		teamArg = *in.TeamID
	}
	var projArg interface{}
	if in.ProjectID != nil {
		projArg = *in.ProjectID
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO governance.approval_requests (
			id, org_id, team_id, request_type, resource_type, resource_id,
			requested_by, reason, status,
			required_approvals, current_approvals, target_transition, project_id,
			expires_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, 'pending',
			$9, 0, NULLIF($10, ''), $11,
			$12, $13
		)
	`,
		id, in.OrgID, teamArg, in.RequestType, in.ResourceType, in.ResourceID,
		in.RequestedBy, in.Reason,
		in.RequiredApprovals, in.TargetTransition, projArg,
		expires, now,
	)
	if err != nil {
		return nil, fmt.Errorf("governance: insert approval request: %w", err)
	}

	out := &ApprovalRequest{
		ID:                id.String(),
		OrgID:             in.OrgID.String(),
		RequestType:       in.RequestType,
		ResourceType:      in.ResourceType,
		ResourceID:        in.ResourceID.String(),
		RequestedBy:       in.RequestedBy.String(),
		Reason:            in.Reason,
		Status:            "pending",
		RequiredApprovals: in.RequiredApprovals,
		CurrentApprovals:  0,
		TargetTransition:  in.TargetTransition,
		ExpiresAt:         &expires,
		CreatedAt:         now,
	}
	if in.TeamID != nil {
		out.TeamID = in.TeamID.String()
	}
	if in.ProjectID != nil {
		out.ProjectID = in.ProjectID.String()
	}
	return out, nil
}

// DecideApproval records a per-approver decision and applies the two-person
// rule. Behavior:
//
//   - Requester cannot decide on their own request → ErrSelfApprovalForbidden.
//   - The same approver decides twice → ErrDuplicateDecision.
//   - The request is no longer pending → ErrAlreadyDecided.
//   - The request has expired → ErrExpired.
//   - A 'reject' decision short-circuits to status='rejected' immediately.
//   - When approve count reaches required_approvals the row flips to 'approved'.
//
// Returns the updated ApprovalRequest row on success.
//
// reqID accepts the approval request's UUID as a string (matching
// ApprovalRequest.ID) — invalid UUIDs return ErrApprovalNotFound.
func DecideApproval(ctx context.Context, pool *pgxpool.Pool, reqID string, decidedBy uuid.UUID, decision, reason string) (*ApprovalRequest, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}
	if decision != "approve" && decision != "reject" {
		return nil, fmt.Errorf("governance: invalid decision %q (must be approve|reject)", decision)
	}
	parsedReqID, err := uuid.Parse(reqID)
	if err != nil {
		return nil, ErrApprovalNotFound
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("governance: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		orgID, requestedBy uuid.UUID
		teamID, projectID  *uuid.UUID
		requestType        string
		resourceType       string
		resourceID         uuid.UUID
		req                ApprovalRequest
		targetTransition   *string
		expiresAt          *time.Time
		decidedByDB        *uuid.UUID
		decisionReasonDB   *string
		decidedAtDB        *time.Time
	)

	err = tx.QueryRow(ctx, `
		SELECT id, org_id, team_id, request_type, resource_type, resource_id,
		       requested_by, reason, status,
		       required_approvals, current_approvals, target_transition, project_id,
		       decided_by, decision_reason, decided_at,
		       expires_at, created_at
		FROM governance.approval_requests
		WHERE id = $1
		FOR UPDATE
	`, parsedReqID).Scan(
		&req.ID, &orgID, &teamID, &requestType, &resourceType, &resourceID,
		&requestedBy, &req.Reason, &req.Status,
		&req.RequiredApprovals, &req.CurrentApprovals, &targetTransition, &projectID,
		&decidedByDB, &decisionReasonDB, &decidedAtDB,
		&expiresAt, &req.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrApprovalNotFound
		}
		return nil, fmt.Errorf("governance: load approval request: %w", err)
	}

	req.OrgID = orgID.String()
	req.RequestType = requestType
	req.ResourceType = resourceType
	req.ResourceID = resourceID.String()
	req.RequestedBy = requestedBy.String()
	if teamID != nil {
		req.TeamID = teamID.String()
	}
	if projectID != nil {
		req.ProjectID = projectID.String()
	}
	if targetTransition != nil {
		req.TargetTransition = *targetTransition
	}
	req.ExpiresAt = expiresAt
	if decidedByDB != nil {
		req.DecidedBy = decidedByDB.String()
	}
	if decisionReasonDB != nil {
		req.DecisionReason = *decisionReasonDB
	}
	req.DecidedAt = decidedAtDB

	// Pre-checks (status / expiry / self-approval).
	if req.Status != "pending" {
		return nil, ErrAlreadyDecided
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return nil, ErrExpired
	}
	if requestedBy == decidedBy {
		return nil, ErrSelfApprovalForbidden
	}

	// Insert the per-approver decision; UNIQUE (request_id, decided_by) enforces dedup.
	_, err = tx.Exec(ctx, `
		INSERT INTO governance.approval_decisions
			(approval_request_id, decided_by, decision, reason)
		VALUES ($1, $2, $3, $4)
	`, parsedReqID, decidedBy, decision, reason)
	if err != nil {
		if pgxSQLState(err) == "23505" {
			return nil, ErrDuplicateDecision
		}
		return nil, fmt.Errorf("governance: insert approval decision: %w", err)
	}

	// Recompute approve count from the source of truth.
	var approves int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM governance.approval_decisions
		WHERE approval_request_id = $1 AND decision = 'approve'
	`, parsedReqID).Scan(&approves); err != nil {
		return nil, fmt.Errorf("governance: count approvals: %w", err)
	}

	newStatus := "pending"
	switch {
	case decision == "reject":
		newStatus = "rejected"
	case approves >= req.RequiredApprovals:
		newStatus = "approved"
	}

	now := time.Now()
	if newStatus != "pending" {
		_, err = tx.Exec(ctx, `
			UPDATE governance.approval_requests
			   SET status = $1,
			       current_approvals = $2,
			       decided_by = $3,
			       decision_reason = $4,
			       decided_at = $5
			 WHERE id = $6
		`, newStatus, approves, decidedBy, reason, now, parsedReqID)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE governance.approval_requests
			   SET current_approvals = $1
			 WHERE id = $2
		`, approves, parsedReqID)
	}
	if err != nil {
		return nil, fmt.Errorf("governance: update approval request: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("governance: commit: %w", err)
	}

	req.Status = newStatus
	req.CurrentApprovals = approves
	if newStatus != "pending" {
		req.DecidedBy = decidedBy.String()
		req.DecisionReason = reason
		req.DecidedAt = &now
	}
	return &req, nil
}

// pgxSQLState extracts the PostgreSQL SQLSTATE from a wrapped pgx error.
// Returns "" for non-pg errors.
func pgxSQLState(err error) string {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState()
	}
	return ""
}
