package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

// ScanWebhookPayload is the JSON body sent to webhook endpoints when a scan
// completes. Recipients verify the X-Signature header against a shared secret.
type ScanWebhookPayload struct {
	Event     string `json:"event"`
	ScanID    string `json:"scan_id"`
	ProjectID string `json:"project_id"`
	ScanType  string `json:"scan_type"`
	Status    string `json:"status"`
	Findings  int    `json:"findings_count"`
	Timestamp string `json:"timestamp"`
}

// DispatchScanWebhooks sends a scan.completed event to all active webhooks
// for the finding's org. Called from the scan status update path.
func DispatchScanWebhooks(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger, scanID string) {
	// Load scan metadata.
	var projectID, scanType, status, orgID string
	var findingsCount int
	err := pool.QueryRow(ctx,
		`SELECT sj.project_id::text, sj.scan_type, sj.status,
		        p.org_id::text,
		        (SELECT count(*) FROM findings.findings WHERE scan_job_id = sj.id)
		   FROM scans.scan_jobs sj
		   JOIN core.projects p ON p.id = sj.project_id
		  WHERE sj.id = $1`, scanID,
	).Scan(&projectID, &scanType, &status, &orgID, &findingsCount)
	if err != nil {
		return
	}

	if status != "completed" && status != "failed" {
		return
	}

	payload := ScanWebhookPayload{
		Event:     "scan." + status,
		ScanID:    scanID,
		ProjectID: projectID,
		ScanType:  scanType,
		Status:    status,
		Findings:  findingsCount,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)

	// Load webhook URLs for this org. Secret for signing is the platform
	// MSG_SIGNING_KEY (same as NATS message signing).
	signingKey := os.Getenv("MSG_SIGNING_KEY")
	rows, err := pool.Query(ctx,
		`SELECT url FROM governance.webhook_configs
		  WHERE org_id = $1 AND enabled = true
		    AND ('scan.completed' = ANY(events) OR 'scan.*' = ANY(events) OR events = '{}')`,
		orgID)
	if err != nil {
		return
	}
	defer rows.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	for rows.Next() {
		var url string
		if rows.Scan(&url) != nil {
			continue
		}
		go deliverWebhook(client, logger, url, signingKey, body)
	}
}

func deliverWebhook(client *http.Client, logger zerolog.Logger, url, secret string, body []byte) {
	sig := signPayload(secret, body)
	start := time.Now()
	for attempt := 0; attempt < 3; attempt++ {
		observability.WebhookDeliveries.WithLabelValues("scan.completed", "attempted").Inc()
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SentinelCore-Signature", sig)
		req.Header.Set("X-SentinelCore-Event", "scan.completed")

		resp, err := client.Do(req)
		if err != nil {
			observability.WebhookDeliveries.WithLabelValues("scan.completed", "error").Inc()
			logger.Warn().Err(err).Str("url", url).Int("attempt", attempt+1).Msg("webhook delivery failed")
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			observability.WebhookDeliveries.WithLabelValues("scan.completed", "success").Inc()
			observability.WebhookLatency.WithLabelValues("scan.completed").Observe(time.Since(start).Seconds())
			return
		}
		observability.WebhookDeliveries.WithLabelValues("scan.completed", "non_2xx").Inc()
		logger.Warn().Str("url", url).Int("status", resp.StatusCode).Int("attempt", attempt+1).Msg("webhook non-2xx")
		time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
	}
}

func signPayload(secret string, body []byte) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("sha256=%s", hex.EncodeToString(mac.Sum(nil)))
}
