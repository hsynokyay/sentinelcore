package updater

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Service implements the Update Manager HTTP handlers.
type Service struct {
	verifier *Verifier
	lockdown *LockdownManager
	trust    *TrustStore
	stageDir string
}

// NewService creates a new Update Manager service.
func NewService(verifier *Verifier, lockdown *LockdownManager, trust *TrustStore, stageDir string) *Service {
	return &Service{
		verifier: verifier,
		lockdown: lockdown,
		trust:    trust,
		stageDir: stageDir,
	}
}

// HandleImport receives a bundle upload, writes it to a staging area, and
// runs the full verification pipeline.
func (s *Service) HandleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Write uploaded bundle to staging dir
	if err := os.MkdirAll(s.stageDir, 0755); err != nil {
		http.Error(w, "cannot create staging directory", http.StatusInternalServerError)
		return
	}

	tmpFile, err := os.CreateTemp(s.stageDir, "bundle-*.tar.gz")
	if err != nil {
		http.Error(w, "cannot create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, r.Body); err != nil {
		tmpFile.Close()
		http.Error(w, "failed to read bundle", http.StatusBadRequest)
		return
	}
	tmpFile.Close()

	result, err := s.verifier.VerifyBundle(r.Context(), tmpFile.Name())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !result.Accepted {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	json.NewEncoder(w).Encode(result)
}

// HandleVerify performs a dry-run verification from a file path provided in the request body.
func (s *Service) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		BundlePath string `json:"bundle_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	absPath, err := filepath.Abs(req.BundlePath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	result, err := s.verifier.VerifyBundle(r.Context(), absPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleTrustStatus returns the current trust state from the database.
func (s *Service) HandleTrustStatus(w http.ResponseWriter, r *http.Request) {
	state, err := s.trust.GetTrustState(r.Context())
	if err != nil {
		http.Error(w, "cannot read trust state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

// HandleLockdownEnable activates update lockdown mode.
func (s *Service) HandleLockdownEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Reason = "manual lockdown"
	}

	if err := s.lockdown.Enable(r.Context(), req.Reason); err != nil {
		http.Error(w, "failed to enable lockdown: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "lockdown enabled"})
}

// HandleLockdownDisable deactivates update lockdown mode.
func (s *Service) HandleLockdownDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.lockdown.Disable(r.Context()); err != nil {
		http.Error(w, "failed to disable lockdown: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "lockdown disabled"})
}
