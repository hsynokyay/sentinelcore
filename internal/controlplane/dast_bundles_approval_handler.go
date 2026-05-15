package controlplane

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// ApproveBundleRequest is the body for POST /api/v1/dast/bundles/{id}/approve.
type ApproveBundleRequest struct {
	TTLSeconds int        `json:"ttl_seconds"`
	ACL        []aclEntry `json:"acl"`
}

// RejectBundleRequest is the body for POST /api/v1/dast/bundles/{id}/reject.
type RejectBundleRequest struct {
	Reason string `json:"reason"`
}

// PendingBundle is the list-pending response item.
type PendingBundle struct {
	ID              string `json:"id"`
	CustomerID      string `json:"customer_id"`
	ProjectID       string `json:"project_id"`
	TargetHost      string `json:"target_host"`
	Type            string `json:"type"`
	CreatedByUserID string `json:"created_by_user_id"`
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at"`
}

// Approve handles POST /api/v1/dast/bundles/{id}/approve.
func (h *BundlesHandler) Approve(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		http.Error(w, "bundle store not configured", http.StatusServiceUnavailable)
		return
	}
	user := auth.GetUser(r.Context())
	if user == nil || user.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := pathSegmentBefore(r.URL.Path, "/approve")
	if id == "" {
		http.Error(w, "missing bundle id", http.StatusBadRequest)
		return
	}
	var req ApproveBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 86400
	}
	if req.TTLSeconds > 7*86400 {
		http.Error(w, "ttl_seconds exceeds 7 days", http.StatusBadRequest)
		return
	}
	if err := h.store.Approve(r.Context(), id, user.UserID, req.TTLSeconds); err != nil {
		if isFourEyesError(err) {
			http.Error(w, "4-eyes: recorder cannot approve own recording", http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, acl := range req.ACL {
		if err := h.store.AddACL(r.Context(), id, acl.ProjectID, acl.ScopeID); err != nil {
			http.Error(w, "acl save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// Reject handles POST /api/v1/dast/bundles/{id}/reject.
func (h *BundlesHandler) Reject(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		http.Error(w, "bundle store not configured", http.StatusServiceUnavailable)
		return
	}
	user := auth.GetUser(r.Context())
	if user == nil || user.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := pathSegmentBefore(r.URL.Path, "/reject")
	if id == "" {
		http.Error(w, "missing bundle id", http.StatusBadRequest)
		return
	}
	var req RejectBundleRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.store.Reject(r.Context(), id, user.UserID, req.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListPending handles GET /api/v1/dast/bundles?status=pending_review.
func (h *BundlesHandler) ListPending(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		http.Error(w, "bundle store not configured", http.StatusServiceUnavailable)
		return
	}
	user := auth.GetUser(r.Context())
	if user == nil || user.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	customerID := user.OrgID
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	items, err := h.store.ListPending(r.Context(), customerID, offset, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]PendingBundle, 0, len(items))
	for _, b := range items {
		out = append(out, PendingBundle{
			ID:              b.ID,
			CustomerID:      b.CustomerID,
			ProjectID:       b.ProjectID,
			TargetHost:      b.TargetHost,
			Type:            b.Type,
			CreatedByUserID: b.CreatedByUserID,
			CreatedAt:       b.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			ExpiresAt:       b.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"bundles": out})
}

func pathSegmentBefore(path, suffix string) string {
	if !strings.HasSuffix(path, suffix) {
		return ""
	}
	trim := strings.TrimSuffix(path, suffix)
	if i := strings.LastIndex(trim, "/"); i >= 0 {
		return trim[i+1:]
	}
	return trim
}

func isFourEyesError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "4-eyes")
}

