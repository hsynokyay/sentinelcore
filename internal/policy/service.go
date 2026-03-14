package policy

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Service implements the Policy Engine HTTP handlers.
type Service struct {
	pool *pgxpool.Pool
}

// NewService creates a new Policy Engine service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// EvaluateRequest is the request body for RBAC evaluation.
type EvaluateRequest struct {
	Role       string `json:"role"`
	Permission string `json:"permission"`
}

// EvaluateResponse is the response body for RBAC evaluation.
type EvaluateResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// HandleEvaluate checks if a role has a specific permission.
func (s *Service) HandleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	allowed := Evaluate(req.Role, req.Permission)
	reason := "denied: insufficient role"
	if allowed {
		reason = "allowed"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(EvaluateResponse{
		Allowed: allowed,
		Reason:  reason,
	})
}

// ScanScopeRequest is the request body for scan scope validation.
type ScanScopeRequest struct {
	TargetID string `json:"target_id"`
}

// ScanScopeResponse is the response body for scan scope validation.
type ScanScopeResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// HandleEvaluateScanScope validates whether a scan target is verified and not expired.
func (s *Service) HandleEvaluateScanScope(w http.ResponseWriter, r *http.Request) {
	var req ScanScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := ValidateScanTarget(r.Context(), s.pool, req.TargetID)
	allowed := err == nil
	reason := "allowed"
	if !allowed {
		reason = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScanScopeResponse{
		Allowed: allowed,
		Reason:  reason,
	})
}
