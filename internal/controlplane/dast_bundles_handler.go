package controlplane

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// BundlesHandler handles DAST auth bundle CRUD endpoints.
type BundlesHandler struct {
	store bundles.BundleStore
}

// NewBundlesHandler creates a BundlesHandler backed by the given BundleStore.
func NewBundlesHandler(store bundles.BundleStore) *BundlesHandler {
	return &BundlesHandler{store: store}
}

type createBundleRequest struct {
	ProjectID         string                     `json:"project_id"`
	TargetHost        string                     `json:"target_host"`
	Type              string                     `json:"type"`
	CapturedSession   bundles.SessionCapture     `json:"captured_session"`
	TTLSeconds        int                        `json:"ttl_seconds"`
	ACL               []aclEntry                 `json:"acl"`
	RecordingMetadata *bundles.RecordingMetadata `json:"recording_metadata,omitempty"`
}

type aclEntry struct {
	ProjectID string  `json:"project_id"`
	ScopeID   *string `json:"scope_id,omitempty"`
}

type createBundleResponse struct {
	BundleID string `json:"bundle_id"`
	Status   string `json:"status"`
}

// Create handles POST /api/v1/dast/bundles.
// Requires an authenticated user (OrgID used as customerID). The bundle is
// stored in status "pending_review" and ACL entries are written atomically.
func (h *BundlesHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r.Context())
	if user == nil || user.OrgID == "" || user.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	customerID := user.OrgID
	userID := user.UserID

	var req createBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ProjectID == "" || req.TargetHost == "" {
		http.Error(w, "invalid request: project_id and target_host are required", http.StatusBadRequest)
		return
	}
	if req.Type != "session_import" && req.Type != "recorded_login" {
		http.Error(w, "invalid type: must be session_import or recorded_login", http.StatusBadRequest)
		return
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 86400
	}
	if req.TTLSeconds > 7*86400 {
		http.Error(w, "ttl_seconds exceeds 7 days", http.StatusBadRequest)
		return
	}

	b := &bundles.Bundle{
		ProjectID:         req.ProjectID,
		TargetHost:        req.TargetHost,
		Type:              req.Type,
		CapturedSession:   req.CapturedSession,
		CreatedByUserID:   userID,
		TTLSeconds:        req.TTLSeconds,
		CreatedAt:         time.Now(),
		RecordingMetadata: req.RecordingMetadata,
	}
	id, err := h.store.Save(r.Context(), b, customerID)
	if err != nil {
		http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for _, acl := range req.ACL {
		if err := h.store.AddACL(r.Context(), id, acl.ProjectID, acl.ScopeID); err != nil {
			http.Error(w, "acl save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createBundleResponse{BundleID: id, Status: "pending_review"})
}

// Revoke handles POST /api/v1/dast/bundles/{id}/revoke.
// Requires an authenticated user. The bundle ID is extracted from the URL path.
func (h *BundlesHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r.Context())
	if user == nil || user.OrgID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract bundle ID from the URL path using Go 1.22+ PathValue, falling back
	// to suffix-strip for environments where the {id} pattern is unavailable.
	id := r.PathValue("id")
	if id == "" {
		// Fallback: strip trailing "/revoke" and take the last path segment.
		path := strings.TrimSuffix(r.URL.Path, "/revoke")
		id = path[strings.LastIndex(path, "/")+1:]
	}
	if id == "" {
		http.Error(w, "missing bundle id", http.StatusBadRequest)
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := h.store.Revoke(r.Context(), id, req.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
