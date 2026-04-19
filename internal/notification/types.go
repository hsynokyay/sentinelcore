package notification

import (
	"encoding/json"
	"time"
)

// MaxRetries is the maximum number of delivery attempts for a webhook.
const MaxRetries = 5

// MaxResponseBodySize is the maximum bytes stored from a webhook response.
const MaxResponseBodySize = 4096

// NotificationEvent represents an event that may trigger notifications and webhooks.
type NotificationEvent struct {
	EventType    string            `json:"event_type"`
	OrgID        string            `json:"org_id"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Data         map[string]string `json:"data,omitempty"`
	Recipients   []string          `json:"recipients,omitempty"`
}

// WebhookConfig stores the configuration for an outbound webhook.
type WebhookConfig struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	Name            string    `json:"name"`
	URL             string    `json:"url"`
	SecretEncrypted []byte    `json:"-"`
	SecretKeyID     string    `json:"secret_key_id,omitempty"`
	Events          []string  `json:"events"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// DeliveryAttempt records an individual webhook delivery attempt.
type DeliveryAttempt struct {
	ID           string          `json:"id"`
	WebhookID    string          `json:"webhook_id"`
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	Status       string          `json:"status"`
	Attempts     int             `json:"attempts"`
	LastAttempt  *time.Time      `json:"last_attempt,omitempty"`
	NextRetry    *time.Time      `json:"next_retry,omitempty"`
	ResponseCode int             `json:"response_code,omitempty"`
	ResponseBody string          `json:"response_body,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}
