package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

// blockedCIDRs contains RFC 1918, loopback, link-local, and cloud metadata ranges
// that webhook URLs must not resolve to, preventing SSRF attacks.
var blockedCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"100.64.0.0/10",
		"198.18.0.0/15",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"0.0.0.0/8",
		"240.0.0.0/4",
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("notification: invalid blocked CIDR %q: %v", cidr, err))
		}
		blockedCIDRs = append(blockedCIDRs, ipNet)
	}
}

// ValidateWebhookURL checks that rawURL is safe for webhook delivery.
// It rejects non-HTTPS URLs (except http://localhost for development),
// URLs with embedded credentials, and URLs that resolve to blocked CIDRs.
func ValidateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("notification: invalid URL: %w", err)
	}

	// Reject embedded credentials.
	if u.User != nil {
		return errors.New("notification: URL must not contain credentials")
	}

	hostname := u.Hostname()
	isLocalhost := hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"

	// Enforce HTTPS, except for localhost in development.
	switch strings.ToLower(u.Scheme) {
	case "https":
		// OK
	case "http":
		if !isLocalhost {
			return errors.New("notification: URL scheme must be HTTPS")
		}
	default:
		return fmt.Errorf("notification: unsupported URL scheme %q", u.Scheme)
	}

	// Skip CIDR check for localhost HTTP (development use).
	if isLocalhost && strings.ToLower(u.Scheme) == "http" {
		return nil
	}

	// Resolve hostname and check against blocked CIDRs.
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return fmt.Errorf("notification: cannot resolve host %q: %w", hostname, err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, blocked := range blockedCIDRs {
			if blocked.Contains(ip) {
				return fmt.Errorf("notification: URL resolves to blocked address %s", ipStr)
			}
		}
	}

	return nil
}

// SignPayload computes an HMAC-SHA256 signature of payload using secret,
// returning the hex-encoded result.
func SignPayload(payload []byte, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature performs a constant-time comparison of an HMAC-SHA256
// signature against the expected value.
func VerifySignature(payload []byte, secret []byte, signature string) bool {
	expected := SignPayload(payload, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// CreateWebhookConfig inserts a new webhook configuration with RLS enforcement.
func CreateWebhookConfig(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, config *WebhookConfig) error {
	if pool == nil {
		return errors.New("notification: pool is nil")
	}
	if config == nil {
		return errors.New("notification: webhook config is nil")
	}

	if config.ID == "" {
		config.ID = uuid.New().String()
	}
	config.OrgID = orgID
	now := time.Now()
	config.CreatedAt = now
	config.UpdatedAt = now

	return tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO governance.webhook_configs (
				id, org_id, name, url, secret_encrypted, secret_key_id,
				events, enabled, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			config.ID, config.OrgID, config.Name, config.URL,
			config.SecretEncrypted, config.SecretKeyID,
			config.Events, config.Enabled, config.CreatedAt, config.UpdatedAt,
		)
		return err
	})
}

// ListWebhookConfigs returns all webhook configurations for the org.
func ListWebhookConfigs(ctx context.Context, pool *pgxpool.Pool, userID, orgID string) ([]WebhookConfig, error) {
	if pool == nil {
		return nil, errors.New("notification: pool is nil")
	}

	var results []WebhookConfig
	err := tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, org_id, name, url, secret_encrypted, secret_key_id,
			       events, enabled, created_at, updated_at
			  FROM governance.webhook_configs
			 ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var c WebhookConfig
			if scanErr := rows.Scan(
				&c.ID, &c.OrgID, &c.Name, &c.URL,
				&c.SecretEncrypted, &c.SecretKeyID,
				&c.Events, &c.Enabled, &c.CreatedAt, &c.UpdatedAt,
			); scanErr != nil {
				return scanErr
			}
			results = append(results, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// DeleteWebhookConfig removes a webhook configuration with RLS enforcement.
func DeleteWebhookConfig(ctx context.Context, pool *pgxpool.Pool, userID, orgID, id string) error {
	if pool == nil {
		return errors.New("notification: pool is nil")
	}

	return tenant.TxUser(ctx, pool, orgID, userID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			DELETE FROM governance.webhook_configs
			 WHERE id = $1`, id)
		return err
	})
}

// RecordDeliveryAttempt inserts a webhook delivery attempt record.
// This operates without RLS and is intended for the delivery worker.
func RecordDeliveryAttempt(ctx context.Context, pool *pgxpool.Pool, attempt *DeliveryAttempt) error {
	if pool == nil {
		return errors.New("notification: pool is nil")
	}
	if attempt == nil {
		return errors.New("notification: delivery attempt is nil")
	}

	if attempt.ID == "" {
		attempt.ID = uuid.New().String()
	}
	if attempt.CreatedAt.IsZero() {
		attempt.CreatedAt = time.Now()
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, `
		INSERT INTO governance.webhook_deliveries (
			id, webhook_id, event_type, payload, status, attempts,
			last_attempt, next_retry, response_code, response_body, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		attempt.ID, attempt.WebhookID, attempt.EventType, attempt.Payload,
		attempt.Status, attempt.Attempts, attempt.LastAttempt, attempt.NextRetry,
		attempt.ResponseCode, attempt.ResponseBody, attempt.CreatedAt,
	)
	return err
}

// GetPendingDeliveries returns delivery attempts that are ready for retry.
// This operates without RLS and is intended for the delivery worker.
func GetPendingDeliveries(ctx context.Context, pool *pgxpool.Pool, limit int) ([]DeliveryAttempt, error) {
	if pool == nil {
		return nil, errors.New("notification: pool is nil")
	}
	if limit <= 0 {
		limit = 50
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	rows, err := conn.Query(ctx, `
		SELECT id, webhook_id, event_type, payload, status, attempts,
		       last_attempt, next_retry, response_code, response_body, created_at
		  FROM governance.webhook_deliveries
		 WHERE status IN ('pending','failed')
		   AND (next_retry IS NULL OR next_retry <= now())
		 ORDER BY created_at
		 LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []DeliveryAttempt
	for rows.Next() {
		var d DeliveryAttempt
		if scanErr := rows.Scan(
			&d.ID, &d.WebhookID, &d.EventType, &d.Payload,
			&d.Status, &d.Attempts, &d.LastAttempt, &d.NextRetry,
			&d.ResponseCode, &d.ResponseBody, &d.CreatedAt,
		); scanErr != nil {
			return nil, scanErr
		}
		results = append(results, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// validateURL is the URL validation function used by DeliverWebhook.
// It defaults to ValidateWebhookURL but can be overridden in tests.
var validateURL = ValidateWebhookURL

// httpClient is the HTTP client used by DeliverWebhook.
// It defaults to http.DefaultClient but can be overridden in tests.
var httpClient = http.DefaultClient

// DeliverWebhook sends a JSON payload to the webhook URL, signs it with the
// provided secret, and returns a DeliveryAttempt recording the result.
// The URL is re-validated at delivery time to prevent SSRF via DNS rebinding.
func DeliverWebhook(ctx context.Context, config *WebhookConfig, eventType string, payload json.RawMessage, secret []byte) (*DeliveryAttempt, error) {
	if config == nil {
		return nil, errors.New("notification: webhook config is nil")
	}

	// Re-validate URL at delivery time to guard against DNS rebinding.
	if err := validateURL(config.URL); err != nil {
		return nil, fmt.Errorf("notification: delivery URL validation failed: %w", err)
	}

	sig := SignPayload(payload, secret)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("notification: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Signature", "sha256="+sig)
	req.Header.Set("X-Sentinel-Event", eventType)

	now := time.Now()
	attempt := &DeliveryAttempt{
		ID:          uuid.New().String(),
		WebhookID:   config.ID,
		EventType:   eventType,
		Payload:     payload,
		Attempts:    1,
		LastAttempt: &now,
		CreatedAt:   now,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		attempt.Status = "failed"
		attempt.ResponseBody = truncate(err.Error(), MaxResponseBodySize)
		return attempt, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(MaxResponseBodySize)+1))
	attempt.ResponseCode = resp.StatusCode
	attempt.ResponseBody = truncate(string(body), MaxResponseBodySize)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		attempt.Status = "delivered"
	} else {
		attempt.Status = "failed"
	}

	return attempt, nil
}

// truncate returns s truncated to maxLen bytes.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
