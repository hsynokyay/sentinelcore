package api

// approvals_vote.go — Phase 9 §4.1 multi-approver vote endpoints.
//
// Adds two NEW routes on top of the existing governance.go surface:
//
//   POST /api/v1/approvals/{id}/approve
//   POST /api/v1/approvals/{id}/reject
//
// Both go through pkg/governance/approval_fsm so the state-machine
// invariants (requester ≠ approver, no duplicate vote, terminal
// refusal, quorum) are unit-testable. The existing DecideApproval
// single-vote handler stays for backward compat until the UI
// migrates.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/pkg/audit"
	gov "github.com/sentinelcore/sentinelcore/pkg/governance"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

type approvalVoteReq struct {
	Reason string `json:"reason"`
}

// ApproveRequest is POST /approvals/{id}/approve.
func (h *Handlers) ApproveRequest(w http.ResponseWriter, r *http.Request) {
	h.voteOnApproval(w, r, gov.DecisionApprove, "approval.approved")
}

// RejectRequest is POST /approvals/{id}/reject.
func (h *Handlers) RejectRequest(w http.ResponseWriter, r *http.Request) {
	h.voteOnApproval(w, r, gov.DecisionReject, "approval.rejected")
}

func (h *Handlers) voteOnApproval(w http.ResponseWriter, r *http.Request,
	d gov.ApprovalDecision, auditAction string) {

	user := requireAuth(w, r)
	if user == nil {
		return
	}
	id := r.PathValue("id")
	var body approvalVoteReq
	_ = decodeJSON(r, &body)

	var (
		transitionErr error
		newState      gov.ApprovalState
		notFound      bool
	)

	err := tenant.TxUser(r.Context(), h.pool, user.OrgID, user.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			var (
				curStatus    string
				requiredAppr int
				approvals    int
				rejections   int
				requesterID  string
				expiresAt    *time.Time
			)
			if err := tx.QueryRow(ctx, `
				SELECT status, required_approvers, approvals_received,
				       rejections_received, requested_by::text, expires_at
				  FROM governance.approval_requests
				 WHERE id = $1`, id,
			).Scan(&curStatus, &requiredAppr, &approvals, &rejections,
				&requesterID, &expiresAt); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					notFound = true
					return nil
				}
				return err
			}

			// Auto-expire mid-flight if past expires_at.
			if (curStatus == "pending" || curStatus == "reviewed") &&
				expiresAt != nil && time.Now().After(*expiresAt) {
				if _, err := tx.Exec(ctx,
					`UPDATE governance.approval_requests SET status='expired' WHERE id=$1`,
					id); err != nil {
					return err
				}
				transitionErr = gov.ErrTerminalState
				return nil
			}

			// Collect prior voters (for duplicate-vote guard).
			rows, err := tx.Query(ctx,
				`SELECT approver_id::text FROM governance.approval_approvers WHERE request_id = $1`,
				id)
			if err != nil {
				return err
			}
			var voters []string
			for rows.Next() {
				var v string
				if err := rows.Scan(&v); err != nil {
					rows.Close()
					return err
				}
				voters = append(voters, v)
			}
			rows.Close()

			t, terr := gov.Transition(gov.ApprovalRequestFSM{
				State:              gov.ApprovalState(curStatus),
				RequiredApprovers:  requiredAppr,
				ApprovalsReceived:  approvals,
				RejectionsReceived: rejections,
				RequesterUserID:    requesterID,
				ApproverUserIDs:    voters,
			}, user.UserID, d)
			if terr != nil {
				transitionErr = terr
				return nil
			}

			// Insert vote row (PK + append-only trigger enforce
			// no-duplicate + no-rewrite).
			if _, err := tx.Exec(ctx, `
				INSERT INTO governance.approval_approvers
				    (request_id, approver_id, decision, reason, decided_at)
				VALUES ($1,$2,$3,NULLIF($4,''),now())`,
				id, user.UserID, string(d), body.Reason); err != nil {
				return err
			}
			var decidedAt interface{}
			if gov.IsTerminal(t.NextState) {
				decidedAt = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `
				UPDATE governance.approval_requests
				   SET status = $2,
				       approvals_received = $3,
				       rejections_received = $4,
				       decided_at = COALESCE(decided_at, $5::timestamptz)
				 WHERE id = $1`,
				id, string(t.NextState),
				t.ApprovalsReceived, t.RejectionsReceived, decidedAt); err != nil {
				return err
			}
			newState = t.NextState
			return nil
		})
	if err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("vote on approval")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if notFound {
		writeError(w, http.StatusNotFound, "approval not found", "NOT_FOUND")
		return
	}
	switch {
	case errors.Is(transitionErr, gov.ErrRequesterCannotVote):
		writeError(w, http.StatusForbidden, "requester cannot vote on own request", "FORBIDDEN")
		return
	case errors.Is(transitionErr, gov.ErrDuplicateVote):
		writeError(w, http.StatusConflict, "already voted", "DUPLICATE_VOTE")
		return
	case errors.Is(transitionErr, gov.ErrTerminalState):
		writeError(w, http.StatusConflict, "request is in a terminal state", "TERMINAL_STATE")
		return
	case transitionErr != nil:
		writeError(w, http.StatusBadRequest, transitionErr.Error(), "BAD_REQUEST")
		return
	}

	if h.emitter != nil {
		_ = h.emitter.Emit(r.Context(), audit.AuditEvent{
			ActorType:    "user",
			ActorID:      user.UserID,
			Action:       auditAction,
			ResourceType: "approval",
			ResourceID:   id,
			OrgID:        user.OrgID,
			Result:       audit.ResultSuccess,
			Details: map[string]any{
				"decision": string(d),
				"state":    string(newState),
			},
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": string(newState)})
}
