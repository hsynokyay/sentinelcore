package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// riskEventJSON is the wire format for audit.risk_events. Fields mirror
// the table; before_value / after_value are emitted as raw JSON so the
// UI can render diffs without a second decode.
type riskEventJSON struct {
	ID          int64           `json:"id"`
	EventType   string          `json:"event_type"`
	OccurredAt  time.Time       `json:"occurred_at"`
	ActorType   string          `json:"actor_type"`
	ActorID     string          `json:"actor_id"`
	AuditLogID  int64           `json:"audit_log_id"`
	Before      json.RawMessage `json:"before,omitempty"`
	After       json.RawMessage `json:"after,omitempty"`
	Note        string          `json:"note,omitempty"`
	IsMaterial  bool            `json:"is_material"`
}

// RiskHistory handles GET /api/v1/risks/{id}/history.
//
// Permission: risks.read (caller must be able to see the risk itself; the
// history query is tenant-scoped via the org_id predicate, so a cross-tenant
// risk_id returns an empty list rather than 404).
//
// Query params:
//   limit         default 50, max 200
//   include_noise default false — include non-material events
func (h *Handlers) RiskHistory(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	riskID := r.PathValue("id")
	if riskID == "" {
		writeError(w, http.StatusBadRequest, "missing risk id", "BAD_REQUEST")
		return
	}

	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	includeNoise := r.URL.Query().Get("include_noise") == "true"

	materialClause := ""
	if !includeNoise {
		materialClause = "AND is_material = true"
	}

	rows, err := h.pool.Query(r.Context(), fmt.Sprintf(`
		SELECT id, event_type, occurred_at, actor_type, actor_id,
		       audit_log_id,
		       COALESCE(before_value, 'null'::jsonb),
		       COALESCE(after_value, 'null'::jsonb),
		       COALESCE(note, ''),
		       is_material
		FROM audit.risk_events
		WHERE risk_id = $1 AND org_id = $2 %s
		ORDER BY occurred_at DESC, id DESC
		LIMIT $3
	`, materialClause), riskID, p.OrgID, limit)
	if err != nil {
		h.logger.Error().Err(err).Str("risk_id", riskID).Msg("risk history query")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	defer rows.Close()

	out := make([]riskEventJSON, 0, limit)
	for rows.Next() {
		var e riskEventJSON
		var before, after []byte
		if err := rows.Scan(&e.ID, &e.EventType, &e.OccurredAt,
			&e.ActorType, &e.ActorID, &e.AuditLogID,
			&before, &after, &e.Note, &e.IsMaterial); err != nil {
			h.logger.Error().Err(err).Msg("risk history scan")
			writeError(w, http.StatusInternalServerError, "scan", "INTERNAL")
			return
		}
		if string(before) != "null" {
			e.Before = before
		}
		if string(after) != "null" {
			e.After = after
		}
		out = append(out, e)
	}

	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}
