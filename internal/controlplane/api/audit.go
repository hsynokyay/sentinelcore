package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

type auditEventResponse struct {
	EventID      string `json:"event_id"`
	Timestamp    string `json:"timestamp"`
	ActorType    string `json:"actor_type"`
	ActorID      string `json:"actor_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Result       string `json:"result"`
}

// ListAuditEvents returns paginated audit log entries with optional filters.
func (h *Handlers) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "audit.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	action := r.URL.Query().Get("action")
	actorID := r.URL.Query().Get("actor_id")
	resourceType := r.URL.Query().Get("resource_type")
	dateFrom := r.URL.Query().Get("date_from")
	dateTo := r.URL.Query().Get("date_to")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50
	offset := 0
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 200 {
			limit = v
		}
	}
	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
			offset = v
		}
	}

	var events []auditEventResponse

	err := db.WithRLS(r.Context(), h.pool, user.UserID, user.OrgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		query := `SELECT event_id, timestamp, actor_type, actor_id, action, resource_type, resource_id, result
				  FROM audit.audit_log WHERE 1=1`
		args := []any{}
		argIdx := 1

		if action != "" {
			query += fmt.Sprintf(" AND action = $%d", argIdx)
			args = append(args, action)
			argIdx++
		}
		if actorID != "" {
			query += fmt.Sprintf(" AND actor_id = $%d", argIdx)
			args = append(args, actorID)
			argIdx++
		}
		if resourceType != "" {
			query += fmt.Sprintf(" AND resource_type = $%d", argIdx)
			args = append(args, resourceType)
			argIdx++
		}
		if dateFrom != "" {
			query += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
			args = append(args, dateFrom)
			argIdx++
		}
		if dateTo != "" {
			query += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
			args = append(args, dateTo)
			argIdx++
		}

		query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, limit, offset)

		rows, err := conn.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var e auditEventResponse
			var ts time.Time
			if err := rows.Scan(&e.EventID, &ts, &e.ActorType, &e.ActorID, &e.Action, &e.ResourceType, &e.ResourceID, &e.Result); err != nil {
				return err
			}
			e.Timestamp = ts.Format(time.RFC3339)
			events = append(events, e)
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list audit events")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if events == nil {
		events = []auditEventResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"limit":  limit,
		"offset": offset,
	})
}
