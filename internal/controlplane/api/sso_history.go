package api

import (
	"net/http"
	"strconv"
	"time"
)

// historyEventJSON is the wire format. Secrets / raw tokens never
// populate this — claims_redacted is already masked at write time in
// the callback handler.
type historyEventJSON struct {
	ID             int64          `json:"id"`
	OccurredAt     time.Time      `json:"occurred_at"`
	Outcome        string         `json:"outcome"`
	ErrorCode      string         `json:"error_code,omitempty"`
	ExternalID     string         `json:"external_id,omitempty"`
	Email          string         `json:"email,omitempty"`
	RoleGranted    string         `json:"role_granted,omitempty"`
	ClaimsRedacted map[string]any `json:"claims_redacted,omitempty"`
	IPAddress      string         `json:"ip_address,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
}

// SSOLoginHistory handles
//
//	GET /api/v1/sso/providers/{id}/history?limit=50 — sso.manage.
//
// Returns the most recent login attempts for a provider (default 50,
// max 200). The underlying retention trigger caps the table at 500
// rows per provider.
func (h *Handlers) SSOLoginHistory(w http.ResponseWriter, r *http.Request) {
	if h.ssoEvents == nil {
		writeError(w, http.StatusServiceUnavailable, "sso disabled", "SSO_DISABLED")
		return
	}
	providerID := r.PathValue("id")

	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}

	events, err := h.ssoEvents.ListByProvider(r.Context(), providerID, limit)
	if err != nil {
		h.logger.Error().Err(err).Str("provider_id", providerID).Msg("list sso history")
		writeError(w, http.StatusInternalServerError, "internal", "INTERNAL")
		return
	}

	out := make([]historyEventJSON, 0, len(events))
	for _, e := range events {
		out = append(out, historyEventJSON{
			ID:             e.ID,
			OccurredAt:     e.OccurredAt,
			Outcome:        e.Outcome,
			ErrorCode:      e.ErrorCode,
			ExternalID:     e.ExternalID,
			Email:          e.Email,
			RoleGranted:    e.RoleGranted,
			ClaimsRedacted: e.ClaimsRedacted,
			IPAddress:      e.IPAddress,
			UserAgent:      e.UserAgent,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}
