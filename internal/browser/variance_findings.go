package browser

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sentinelcore/sentinelcore/internal/dast"
)

// VarianceObservationType categorizes auth-state variance observations.
type VarianceObservationType string

const (
	VarAuthOnlyRoute      VarianceObservationType = "auth_only_route"
	VarAnonOnlyRoute      VarianceObservationType = "anon_only_route"
	VarAuthOnlyForm       VarianceObservationType = "auth_only_form"
	VarAnonOnlyForm       VarianceObservationType = "anon_only_form"
	VarSurfaceExpansion   VarianceObservationType = "surface_expansion"
)

// VarianceRule maps a variance observation to a security finding.
type VarianceRule struct {
	ID          string                  `json:"id"`
	Type        VarianceObservationType `json:"type"`
	Title       string                  `json:"title"`
	CWEID       int                     `json:"cwe_id"`
	Severity    string                  `json:"severity"`
	Confidence  string                  `json:"confidence"`
	Category    string                  `json:"category"`
}

// VarianceRules defines finding generation rules for auth-state comparison.
var VarianceRules = []VarianceRule{
	{
		ID:         "VARIANCE-001",
		Type:       VarAuthOnlyRoute,
		Title:      "Authenticated-only route discovered",
		CWEID:      0, // informational, no direct CWE
		Severity:   "info",
		Confidence: "high",
		Category:   "access_control",
	},
	{
		ID:         "VARIANCE-002",
		Type:       VarAnonOnlyRoute,
		Title:      "Route accessible anonymously but not when authenticated",
		CWEID:      284, // CWE-284: Improper Access Control
		Severity:   "medium",
		Confidence: "medium",
		Category:   "access_control",
	},
	{
		ID:         "VARIANCE-003",
		Type:       VarAuthOnlyForm,
		Title:      "State-changing form exposed only to authenticated users",
		CWEID:      0, // informational
		Severity:   "info",
		Confidence: "high",
		Category:   "access_control",
	},
	{
		ID:         "VARIANCE-004",
		Type:       VarAnonOnlyForm,
		Title:      "State-changing form accessible anonymously but hidden when authenticated",
		CWEID:      284,
		Severity:   "high",
		Confidence: "medium",
		Category:   "access_control",
	},
	{
		ID:         "VARIANCE-005",
		Type:       VarSurfaceExpansion,
		Title:      "Significant attack surface expansion with authentication",
		CWEID:      0, // informational
		Severity:   "info",
		Confidence: "high",
		Category:   "attack_surface",
	},
}

// VarianceRuleByType returns the rule matching the given type, or nil.
func VarianceRuleByType(t VarianceObservationType) *VarianceRule {
	for i := range VarianceRules {
		if VarianceRules[i].Type == t {
			return &VarianceRules[i]
		}
	}
	return nil
}

// VarianceAnalysisResult holds the complete output of auth-state comparison.
type VarianceAnalysisResult struct {
	Variance     *AuthStateVariance `json:"variance"`
	Observations []Observation      `json:"observations"`
	Findings     []dast.Finding     `json:"findings"`
}

// AnalyzeVariance generates security findings from auth-state differences.
// Only produces findings backed by directly observed differences.
func AnalyzeVariance(variance *AuthStateVariance, scanJobID string) *VarianceAnalysisResult {
	result := &VarianceAnalysisResult{Variance: variance}

	// Auth-only routes: informational — expected behavior (protected content).
	for _, url := range variance.AuthOnlyURLs {
		rule := VarianceRuleByType(VarAuthOnlyRoute)
		obs := Observation{
			Type:       ObservationType(VarAuthOnlyRoute),
			URL:        url,
			Detail:     fmt.Sprintf("Route %s is only reachable when authenticated", url),
			Confidence: rule.Confidence,
			Severity:   rule.Severity,
			CWEID:      rule.CWEID,
			RuleID:     rule.ID,
		}
		result.Observations = append(result.Observations, obs)
		// Informational — no finding generated for normal auth-only routes
	}

	// Anon-only routes: suspicious — may indicate access control issue.
	for _, url := range variance.AnonOnlyURLs {
		rule := VarianceRuleByType(VarAnonOnlyRoute)
		obs := Observation{
			Type:       ObservationType(VarAnonOnlyRoute),
			URL:        url,
			Detail:     fmt.Sprintf("Route %s is reachable anonymously but not when authenticated — possible access control anomaly", url),
			Confidence: rule.Confidence,
			Severity:   rule.Severity,
			CWEID:      rule.CWEID,
			RuleID:     rule.ID,
		}
		result.Observations = append(result.Observations, obs)
		result.Findings = append(result.Findings, varianceToFinding(obs, scanJobID))
	}

	// Auth-only forms: informational — expected for admin/settings panels.
	for url, fs := range variance.AuthOnlyForms {
		rule := VarianceRuleByType(VarAuthOnlyForm)
		obs := Observation{
			Type:       ObservationType(VarAuthOnlyForm),
			URL:        url,
			Detail:     fmt.Sprintf("%d forms on %s are only visible when authenticated (actions: %v)", fs.Count, url, fs.Actions),
			Confidence: rule.Confidence,
			Severity:   rule.Severity,
			CWEID:      rule.CWEID,
			RuleID:     rule.ID,
		}
		result.Observations = append(result.Observations, obs)
		// Informational — no finding for expected auth-only forms
	}

	// Anon-only forms: concerning — forms that disappear after auth may indicate
	// hidden endpoints accessible without authentication.
	for url, fs := range variance.AnonOnlyForms {
		rule := VarianceRuleByType(VarAnonOnlyForm)
		obs := Observation{
			Type:       ObservationType(VarAnonOnlyForm),
			URL:        url,
			Detail:     fmt.Sprintf("%d forms on %s are visible anonymously but hidden when authenticated (actions: %v)", fs.Count, url, fs.Actions),
			Confidence: rule.Confidence,
			Severity:   rule.Severity,
			CWEID:      rule.CWEID,
			RuleID:     rule.ID,
		}
		result.Observations = append(result.Observations, obs)
		result.Findings = append(result.Findings, varianceToFinding(obs, scanJobID))
	}

	// Surface expansion: if auth significantly expands the attack surface.
	if variance.AuthPageCount > 0 && variance.AnonPageCount > 0 {
		expansion := float64(variance.AuthPageCount) / float64(variance.AnonPageCount)
		if expansion >= 2.0 && len(variance.AuthOnlyURLs) >= 5 {
			rule := VarianceRuleByType(VarSurfaceExpansion)
			obs := Observation{
				Type:       ObservationType(VarSurfaceExpansion),
				URL:        "",
				Detail:     fmt.Sprintf("Authentication expands visible surface by %.0f%% (%d anon → %d auth pages, %d auth-only routes)", (expansion-1)*100, variance.AnonPageCount, variance.AuthPageCount, len(variance.AuthOnlyURLs)),
				Confidence: rule.Confidence,
				Severity:   rule.Severity,
				CWEID:      rule.CWEID,
				RuleID:     rule.ID,
			}
			result.Observations = append(result.Observations, obs)
			// Informational — no finding, just observation
		}
	}

	return result
}

func varianceToFinding(obs Observation, scanJobID string) dast.Finding {
	fingerprint := computeFingerprint(scanJobID, obs.RuleID, obs.URL, obs.Detail)

	return dast.Finding{
		ID:          uuid.New().String(),
		RuleID:      obs.RuleID,
		Title:       obs.Detail,
		Category:    "access_control",
		Severity:    obs.Severity,
		Confidence:  obs.Confidence,
		URL:         obs.URL,
		Method:      "GET",
		MatchDetail: obs.Detail,
		FoundAt:     time.Now(),
		Evidence: &dast.Evidence{
			ScanJobID: scanJobID,
			RuleID:    obs.RuleID,
			SHA256:    fingerprint,
			Metadata: map[string]string{
				"observation_type": string(obs.Type),
				"finding_source":   "browser_variance",
			},
		},
	}
}
