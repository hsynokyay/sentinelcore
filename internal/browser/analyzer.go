package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentinelcore/sentinelcore/internal/dast"
)

// AnalysisResult holds observations and derived findings from page analysis.
type AnalysisResult struct {
	Observations []Observation  `json:"observations"`
	Findings     []dast.Finding `json:"findings"`
}

// AnalyzePages inspects crawled pages and generates security observations
// and deterministic findings. Only produces findings backed by concrete evidence.
func AnalyzePages(pages []PageResult, scanJobID, projectID string) *AnalysisResult {
	result := &AnalysisResult{}

	for _, page := range pages {
		if page.Error != "" {
			continue
		}
		analyzeCSRF(page, scanJobID, result)
		analyzeMixedContent(page, scanJobID, result)
		analyzeFormHTTP(page, scanJobID, result)
		analyzeInlineScripts(page, scanJobID, result)
		analyzeAutoComplete(page, scanJobID, result)
	}

	return result
}

// analyzeCSRF checks forms for missing CSRF protection.
// Only flags POST/PUT/DELETE forms without CSRF tokens — high confidence.
func analyzeCSRF(page PageResult, scanJobID string, result *AnalysisResult) {
	for _, form := range page.Forms {
		method := strings.ToUpper(form.Method)
		if method != "POST" && method != "PUT" && method != "DELETE" {
			continue
		}
		if form.HasCSRF {
			continue
		}

		obs := Observation{
			Type:       ObsMissingCSRF,
			URL:        page.URL,
			Detail:     fmt.Sprintf("Form action=%q method=%s has no CSRF token field", form.Action, method),
			Element:    fmt.Sprintf("form[action=%q]", form.Action),
			Confidence: "high",
			Severity:   "medium",
			CWEID:      352,
			RuleID:     "BROWSER-001",
		}
		result.Observations = append(result.Observations, obs)
		result.Findings = append(result.Findings, observationToFinding(obs, scanJobID))
	}
}

// analyzeMixedContent detects HTTPS pages whose evidence shows HTTP subresources.
func analyzeMixedContent(page PageResult, scanJobID string, result *AnalysisResult) {
	if !strings.HasPrefix(page.URL, "https://") {
		return
	}
	if page.Evidence == nil {
		return
	}
	for _, entry := range page.Evidence.NetworkLog {
		if strings.HasPrefix(entry.URL, "http://") {
			obs := Observation{
				Type:       ObsMixedContent,
				URL:        page.URL,
				Detail:     fmt.Sprintf("HTTPS page loads HTTP resource: %s", entry.URL),
				Confidence: "high",
				Severity:   "medium",
				CWEID:      319,
				RuleID:     "BROWSER-003",
			}
			result.Observations = append(result.Observations, obs)
			result.Findings = append(result.Findings, observationToFinding(obs, scanJobID))
			break // one finding per page for mixed content
		}
	}
}

// analyzeFormHTTP detects forms that submit to HTTP endpoints from HTTPS pages.
func analyzeFormHTTP(page PageResult, scanJobID string, result *AnalysisResult) {
	if !strings.HasPrefix(page.URL, "https://") {
		return
	}
	for _, form := range page.Forms {
		if strings.HasPrefix(form.Action, "http://") {
			obs := Observation{
				Type:       ObsFormToHTTP,
				URL:        page.URL,
				Detail:     fmt.Sprintf("Form submits to HTTP: %s", form.Action),
				Element:    fmt.Sprintf("form[action=%q]", form.Action),
				Confidence: "high",
				Severity:   "high",
				CWEID:      319,
				RuleID:     "BROWSER-004",
			}
			result.Observations = append(result.Observations, obs)
			result.Findings = append(result.Findings, observationToFinding(obs, scanJobID))
		}
	}
}

// analyzeInlineScripts flags pages with excessive inline scripts.
func analyzeInlineScripts(page PageResult, scanJobID string, result *AnalysisResult) {
	if page.Evidence == nil || page.Evidence.DOMSnapshot == nil {
		return
	}
	if page.Evidence.DOMSnapshot.ScriptTags < 10 {
		return // only flag if >= 10 inline scripts
	}
	obs := Observation{
		Type:       ObsInlineScript,
		URL:        page.URL,
		Detail:     fmt.Sprintf("Page has %d inline script tags", page.Evidence.DOMSnapshot.ScriptTags),
		Confidence: "low",
		Severity:   "info",
		CWEID:      79,
		RuleID:     "BROWSER-007",
	}
	result.Observations = append(result.Observations, obs)
	result.Findings = append(result.Findings, observationToFinding(obs, scanJobID))
}

// analyzeAutoComplete checks for password fields without autocomplete=off.
func analyzeAutoComplete(page PageResult, scanJobID string, result *AnalysisResult) {
	for _, form := range page.Forms {
		for _, field := range form.Fields {
			if field.Type == "password" {
				obs := Observation{
					Type:       ObsAutoComplete,
					URL:        page.URL,
					Detail:     fmt.Sprintf("Password field %q may allow autocomplete", field.Name),
					Element:    fmt.Sprintf("input[name=%q]", field.Name),
					Confidence: "medium",
					Severity:   "low",
					CWEID:      525,
					RuleID:     "BROWSER-006",
				}
				result.Observations = append(result.Observations, obs)
				result.Findings = append(result.Findings, observationToFinding(obs, scanJobID))
				break // one per form
			}
		}
	}
}

// observationToFinding converts a browser observation into a dast.Finding.
// The fingerprint is deterministic: SHA-256(scanJobID | ruleID | url | detail).
func observationToFinding(obs Observation, scanJobID string) dast.Finding {
	fingerprint := computeFingerprint(scanJobID, obs.RuleID, obs.URL, obs.Detail)
	rule := RuleByType(obs.Type)

	title := obs.Detail
	category := ""
	if rule != nil {
		title = rule.Title
		category = rule.Category
	}

	return dast.Finding{
		ID:          uuid.New().String(),
		RuleID:      obs.RuleID,
		Title:       title,
		Category:    category,
		Severity:    obs.Severity,
		Confidence:  obs.Confidence,
		URL:         obs.URL,
		Method:      "GET", // browser observations are from navigation
		Parameter:   obs.Element,
		MatchDetail: obs.Detail,
		FoundAt:     time.Now(),
		Evidence: &dast.Evidence{
			ScanJobID: scanJobID,
			RuleID:    obs.RuleID,
			SHA256:    fingerprint,
			Metadata: map[string]string{
				"observation_type": string(obs.Type),
				"finding_source":   "browser",
			},
		},
	}
}

// computeFingerprint generates a deterministic fingerprint for dedup.
func computeFingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte("|"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
