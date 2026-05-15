package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// reRecordRequest is the JSON body for POST /api/v1/dast/bundles/{id}/re-record.
// The reason is stored as audit context only; downstream review still relies
// on the existing 4-eyes approval gate before the new draft becomes
// approved.
type reRecordRequest struct {
	Reason string `json:"reason"`
}

// reRecordResponse is the success body. The new bundle starts in
// pending_review and the operator drives `dast record --bundle <new_bundle_id>`
// next to fill in actions.
type reRecordResponse struct {
	NewBundleID string `json:"new_bundle_id"`
	Status      string `json:"status"`
}

// ReRecordHandler returns an http.HandlerFunc that supersedes an existing
// auth bundle and creates a fresh draft bundle for the operator to record
// against. The bundle id is read from the {id} URL path segment.
//
// Route: POST /api/v1/dast/bundles/{id}/re-record.
// Authorization is enforced by RequireDASTRole(...RoleRecordingAdmin) at
// the router layer (mirrors the circuit-reset endpoint).
//
// Status codes:
//   - 200 on success (returns new_bundle_id + status="pending_review")
//   - 400 on malformed UUID or missing/invalid body
//   - 401 if no authenticated user is on the request context
//   - 404 when the source bundle is not found for the caller's tenant
//   - 409 when the source is already superseded (operator should follow
//     the existing replacement chain instead)
//   - 500 for any other store error
//   - 503 when the bundle store has not been wired
func ReRecordHandler(store bundles.ReRecordStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			http.Error(w, "bundle store not configured", http.StatusServiceUnavailable)
			return
		}
		user := auth.GetUser(r.Context())
		if user == nil || user.OrgID == "" || user.UserID == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Resolve the bundle id. Prefer Go 1.22+ PathValue; fall back to a
		// suffix-strip parse for tests / direct invocations that don't go
		// through the router.
		id := r.PathValue("id")
		if id == "" {
			path := strings.TrimSuffix(r.URL.Path, "/re-record")
			if i := strings.LastIndex(path, "/"); i >= 0 {
				id = path[i+1:]
			}
		}
		if _, err := uuid.Parse(id); err != nil {
			http.Error(w, "invalid bundle id", http.StatusBadRequest)
			return
		}

		var body reRecordRequest
		// Body is optional — operators may omit a reason for ad-hoc rotates.
		_ = json.NewDecoder(r.Body).Decode(&body)

		nu, err := bundles.ReRecord(r.Context(), store, id, user.UserID, user.OrgID, body.Reason)
		if err != nil {
			switch {
			case errors.Is(err, bundles.ErrBundleNotFound):
				http.Error(w, "bundle not found", http.StatusNotFound)
			case errors.Is(err, bundles.ErrAlreadySuperseded):
				http.Error(w, "bundle already superseded", http.StatusConflict)
			default:
				http.Error(w, "re-record failed: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(reRecordResponse{
			NewBundleID: nu.ID,
			Status:      "pending_review",
		})
	}
}
