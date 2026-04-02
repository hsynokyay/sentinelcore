package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/governance"
	"github.com/sentinelcore/sentinelcore/internal/notification"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

// ListNotificationsHandler returns paged notifications for the authenticated user.
func (h *Handlers) ListNotificationsHandler(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}

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

	notifications, err := notification.ListNotifications(r.Context(), h.pool, user.UserID, user.OrgID, limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list notifications")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if notifications == nil {
		notifications = []governance.Notification{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"notifications": notifications,
		"limit":         limit,
		"offset":        offset,
	})
}

// MarkNotificationRead marks a single notification as read.
func (h *Handlers) MarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}

	id := r.PathValue("id")

	if err := notification.MarkRead(r.Context(), h.pool, user.UserID, user.OrgID, id); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to mark notification read")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "read"})
}

// MarkAllNotificationsRead marks all of the authenticated user's notifications as read.
func (h *Handlers) MarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}

	if err := notification.MarkAllRead(r.Context(), h.pool, user.UserID, user.OrgID); err != nil {
		h.logger.Error().Err(err).Msg("failed to mark all notifications read")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "all_read"})
}

// GetUnreadCount returns the number of unread notifications for the authenticated user.
func (h *Handlers) GetUnreadCount(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}

	count, err := notification.UnreadCount(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to get unread count")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	writeJSON(w, http.StatusOK, map[string]int{"unread_count": count})
}

// ListWebhooks returns all webhook configurations for the org.
func (h *Handlers) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "webhooks.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	configs, err := notification.ListWebhookConfigs(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list webhooks")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if configs == nil {
		configs = []notification.WebhookConfig{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"webhooks": configs})
}

// CreateWebhook creates a new webhook configuration.
func (h *Handlers) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "webhooks.manage") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	var config notification.WebhookConfig
	if err := decodeJSON(r, &config); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	if err := notification.ValidateWebhookURL(config.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}

	if err := notification.CreateWebhookConfig(r.Context(), h.pool, user.UserID, user.OrgID, &config); err != nil {
		h.logger.Error().Err(err).Msg("failed to create webhook")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "webhook.created", "user", user.UserID, "webhook", config.ID, r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, config)
}

// UpdateWebhook updates an existing webhook configuration.
func (h *Handlers) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "webhooks.manage") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	var config notification.WebhookConfig
	if err := decodeJSON(r, &config); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	if err := notification.ValidateWebhookURL(config.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}

	config.ID = id

	// Delete the old config and create the new one (no UpdateWebhookConfig exists)
	if err := notification.DeleteWebhookConfig(r.Context(), h.pool, user.UserID, user.OrgID, id); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to delete old webhook for update")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	if err := notification.CreateWebhookConfig(r.Context(), h.pool, user.UserID, user.OrgID, &config); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to create updated webhook")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "webhook.updated", "user", user.UserID, "webhook", id, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, config)
}

// DeleteWebhook removes a webhook configuration.
func (h *Handlers) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "webhooks.manage") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	if err := notification.DeleteWebhookConfig(r.Context(), h.pool, user.UserID, user.OrgID, id); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to delete webhook")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	h.emitAuditEvent(r.Context(), "webhook.deleted", "user", user.UserID, "webhook", id, r.RemoteAddr, "success")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// TestWebhook sends a test delivery to an existing webhook.
func (h *Handlers) TestWebhook(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "webhooks.manage") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}

	id := r.PathValue("id")

	// Fetch the webhook config to get URL
	configs, err := notification.ListWebhookConfigs(r.Context(), h.pool, user.UserID, user.OrgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list webhooks for test")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}

	var found *notification.WebhookConfig
	for i := range configs {
		if configs[i].ID == id {
			found = &configs[i]
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "webhook not found", "NOT_FOUND")
		return
	}

	testPayload := map[string]any{
		"event":     "webhook.test",
		"timestamp": time.Now().Format(time.RFC3339),
		"webhook_id": id,
		"message":   "This is a test webhook delivery from SentinelCore",
	}
	payloadData, _ := json.Marshal(testPayload)

	attempt, err := notification.DeliverWebhook(r.Context(), found, "webhook.test", payloadData, found.SecretEncrypted)
	if err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to deliver test webhook")
		writeError(w, http.StatusBadGateway, "test delivery failed: "+err.Error(), "DELIVERY_FAILED")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"webhook_id":    id,
		"status":        attempt.Status,
		"response_code": attempt.ResponseCode,
	})
}
