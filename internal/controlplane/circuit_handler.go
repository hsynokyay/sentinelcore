package controlplane

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/replay"
)

// CircuitResetHandler returns an http.HandlerFunc that resets the per-bundle
// replay circuit breaker. The bundle id is read from the {id} URL path
// segment. Responds 204 on success, 400 on a malformed UUID, and 500 if the
// store reports an error.
//
// Route: POST /api/v1/dast/bundles/{id}/circuit/reset.
// Authorization is enforced by RequireDASTRole(...RoleRecordingAdmin) at the
// router layer.
func CircuitResetHandler(store replay.CircuitStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			http.Error(w, "circuit store not configured", http.StatusServiceUnavailable)
			return
		}
		// Go 1.22+ PathValue, with a suffix-strip fallback for tests that
		// build a request without going through the router.
		id := r.PathValue("id")
		if id == "" {
			path := strings.TrimSuffix(r.URL.Path, "/circuit/reset")
			if i := strings.LastIndex(path, "/"); i >= 0 {
				id = path[i+1:]
			}
		}
		bid, err := uuid.Parse(id)
		if err != nil {
			http.Error(w, "invalid bundle id", http.StatusBadRequest)
			return
		}
		if err := store.Reset(r.Context(), bid); err != nil {
			http.Error(w, "reset failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
