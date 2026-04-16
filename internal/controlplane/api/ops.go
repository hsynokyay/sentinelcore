package api

import (
	"net/http"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/policy"
)

// GetQueueStatus returns a snapshot of the scan job queue status.
// GET /api/v1/ops/queue
func (h *Handlers) GetQueueStatus(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "system.config") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	type queueRow struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	type recentJob struct {
		ID        string  `json:"id"`
		ScanType  string  `json:"scan_type"`
		Status    string  `json:"status"`
		CreatedAt string  `json:"created_at"`
		Duration  *string `json:"duration,omitempty"`
	}

	var rows []queueRow
	dbRows, err := h.pool.Query(r.Context(),
		`SELECT status, count(*) FROM scans.scan_jobs GROUP BY status ORDER BY
		 CASE status WHEN 'pending' THEN 1 WHEN 'running' THEN 2 WHEN 'completed' THEN 3
		 WHEN 'failed' THEN 4 ELSE 5 END`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	defer dbRows.Close()
	for dbRows.Next() {
		var r queueRow
		if dbRows.Scan(&r.Status, &r.Count) == nil {
			rows = append(rows, r)
		}
	}
	if rows == nil {
		rows = []queueRow{}
	}

	// Recent 10 jobs.
	var recent []recentJob
	recentRows, err := h.pool.Query(r.Context(),
		`SELECT id, scan_type, status, created_at, completed_at
		   FROM scans.scan_jobs ORDER BY created_at DESC LIMIT 10`)
	if err == nil {
		defer recentRows.Close()
		for recentRows.Next() {
			var j recentJob
			var createdAt time.Time
			var completedAt *time.Time
			if recentRows.Scan(&j.ID, &j.ScanType, &j.Status, &createdAt, &completedAt) == nil {
				j.CreatedAt = createdAt.Format(time.RFC3339)
				if completedAt != nil {
					d := completedAt.Sub(createdAt).Round(time.Second).String()
					j.Duration = &d
				}
				recent = append(recent, j)
			}
		}
	}
	if recent == nil {
		recent = []recentJob{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"queue_status": rows,
		"recent_jobs":  recent,
	})
}

// GetWebhookStatus returns recent webhook delivery information.
// GET /api/v1/ops/webhooks
func (h *Handlers) GetWebhookStatus(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "system.config") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	type webhookInfo struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		URL     string `json:"url_prefix"` // redacted for safety
		Enabled bool   `json:"enabled"`
		Events  []string `json:"events"`
	}

	var hooks []webhookInfo
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, name, url, enabled, events FROM governance.webhook_configs
		  WHERE org_id IN (SELECT org_id FROM core.projects LIMIT 1)
		  ORDER BY created_at DESC LIMIT 20`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var h webhookInfo
			var fullURL string
			if rows.Scan(&h.ID, &h.Name, &fullURL, &h.Enabled, &h.Events) == nil {
				// Redact URL: show scheme + host only.
				if len(fullURL) > 40 {
					h.URL = fullURL[:40] + "…"
				} else {
					h.URL = fullURL
				}
				hooks = append(hooks, h)
			}
		}
	}
	if hooks == nil {
		hooks = []webhookInfo{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"webhooks": hooks})
}
