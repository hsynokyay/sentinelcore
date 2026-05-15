package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// IntegrityCheckRow is the wire format of audit.integrity_checks rows.
type IntegrityCheckRow struct {
	ID               int64      `json:"id"`
	StartedAt        time.Time  `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	PartitionName    string     `json:"partition_name"`
	RowCount         int64      `json:"row_count"`
	FirstRowID       *int64     `json:"first_row_id,omitempty"`
	LastRowID        *int64     `json:"last_row_id,omitempty"`
	Outcome          string     `json:"outcome"`
	FailedRowID      *int64     `json:"failed_row_id,omitempty"`
	FailedKeyVersion *int       `json:"failed_key_version,omitempty"`
	ErrorMessage     string     `json:"error_message,omitempty"`
	CheckedBy        string     `json:"checked_by"`
}

// AuditIntegrity handles GET /api/v1/audit/integrity.
//
// Permission: audit.verify (granted to owner, admin, auditor by
// migration 035). Returns the most recent N verification runs
// (default 50, max 500) across ALL partitions, newest first.
//
// Query params:
//   limit         default 50
//   outcome       optional filter: pass|fail|partial|error
//   partition     optional filter: exact partition_name
//   only_failures convenience: same as outcome!=pass
func (h *Handlers) AuditIntegrity(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.PrincipalFromContext(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
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
	if limit > 500 {
		limit = 500
	}

	outcome := r.URL.Query().Get("outcome")
	partition := r.URL.Query().Get("partition")
	onlyFailures := r.URL.Query().Get("only_failures") == "true"

	where := ""
	args := []any{}
	if outcome != "" {
		args = append(args, outcome)
		where += " AND outcome = $1"
	} else if onlyFailures {
		where += " AND outcome <> 'pass'"
	}
	if partition != "" {
		args = append(args, partition)
		where += " AND partition_name = $" + strconv.Itoa(len(args))
	}

	args = append(args, limit)
	limitPos := len(args)

	sql := "SELECT id, started_at, finished_at, partition_name, " +
		"COALESCE(row_count, 0), first_row_id, last_row_id, " +
		"outcome, failed_row_id, failed_key_version, " +
		"COALESCE(error_message, ''), checked_by " +
		"FROM audit.integrity_checks " +
		"WHERE 1=1" + where + " " +
		"ORDER BY started_at DESC, id DESC LIMIT $" + strconv.Itoa(limitPos)

	rows, err := h.pool.Query(r.Context(), sql, args...)
	if err != nil {
		h.logger.Error().Err(err).Msg("integrity list query")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}
	defer rows.Close()

	out := make([]IntegrityCheckRow, 0, limit)
	for rows.Next() {
		var row IntegrityCheckRow
		if err := rows.Scan(&row.ID, &row.StartedAt, &row.FinishedAt,
			&row.PartitionName, &row.RowCount, &row.FirstRowID, &row.LastRowID,
			&row.Outcome, &row.FailedRowID, &row.FailedKeyVersion,
			&row.ErrorMessage, &row.CheckedBy); err != nil {
			h.logger.Error().Err(err).Msg("integrity scan")
			writeError(w, http.StatusInternalServerError, "scan", "INTERNAL")
			return
		}
		out = append(out, row)
	}

	// Summary — one-shot at the top so dashboards can render the
	// "everything green" banner without counting an array.
	var failing int
	for _, r := range out {
		if r.Outcome != "pass" {
			failing++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"summary": map[string]any{
			"total":   len(out),
			"failing": failing,
			"healthy": failing == 0,
		},
		"runs": out,
	})
}
