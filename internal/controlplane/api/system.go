package api

import "net/http"

// Version info set at build time.
var (
	BuildVersion = "dev"
	BuildCommit  = "unknown"
	BuildDate    = "unknown"
)

// SystemHealth returns health status.
func (h *Handlers) SystemHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// SystemVersion returns version information.
func (h *Handlers) SystemVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": BuildVersion,
		"commit":  BuildCommit,
		"date":    BuildDate,
	})
}
