package correlation

import (
	"math"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// MatchConfig holds tunable parameters for the correlation algorithm.
type MatchConfig struct {
	// Confidence thresholds
	HighThreshold   float64
	MediumThreshold float64
	LowThreshold    float64

	// Temporal windows
	SameCycleWindow time.Duration
	RecentWindow    time.Duration
	WeekWindow      time.Duration
}

// DefaultMatchConfig returns the standard correlation thresholds.
func DefaultMatchConfig() MatchConfig {
	return MatchConfig{
		HighThreshold:   0.80,
		MediumThreshold: 0.50,
		LowThreshold:    0.30,
		SameCycleWindow: time.Hour,
		RecentWindow:    24 * time.Hour,
		WeekWindow:      7 * 24 * time.Hour,
	}
}

// ScoreCWEAxis computes the CWE match score between two findings.
func ScoreCWEAxis(a, b int, hierarchy *CWEHierarchy) float64 {
	if a == 0 || b == 0 {
		return 0.0
	}
	if a == b {
		return 1.0
	}
	// Direct parent match
	if hierarchy.Parent(a) == b || hierarchy.Parent(b) == a {
		return 0.5
	}
	// Shared parent
	if hierarchy.Parent(a) != 0 && hierarchy.Parent(a) == hierarchy.Parent(b) {
		return 0.5
	}
	// Same category
	catA := hierarchy.Category(a)
	catB := hierarchy.Category(b)
	if catA != "" && catA == catB {
		return 0.3
	}
	return 0.0
}

// ScoreParameterAxis computes the parameter match between SAST and DAST findings.
func ScoreParameterAxis(sastSnippet, dastParam string) float64 {
	if dastParam == "" || sastSnippet == "" {
		return 0.0
	}

	// Exact literal match
	if strings.Contains(sastSnippet, dastParam) {
		return 1.0
	}

	// Normalized match: convert both to lowercase, compare snake/camel variants
	normalized := normalizeParamName(dastParam)
	snippetLower := strings.ToLower(sastSnippet)
	if strings.Contains(snippetLower, normalized) {
		return 0.7
	}

	// Try camelCase variant
	camel := snakeToCamel(dastParam)
	if camel != dastParam && strings.Contains(sastSnippet, camel) {
		return 0.7
	}

	return 0.0
}

// ScoreEndpointAxis computes the endpoint match between a DAST URL and a SAST file path.
func ScoreEndpointAxis(dastURL, sastFilePath string) float64 {
	if dastURL == "" || sastFilePath == "" {
		return 0.0
	}

	urlSegments := extractURLSegments(dastURL)
	pathSegments := extractPathSegments(sastFilePath)

	if len(urlSegments) == 0 || len(pathSegments) == 0 {
		return 0.0
	}

	// Count matching segments
	matches := 0
	for _, us := range urlSegments {
		for _, ps := range pathSegments {
			if strings.EqualFold(us, ps) || strings.EqualFold(us, ps+"s") || strings.EqualFold(us+"s", ps) {
				matches++
				break
			}
		}
	}

	if matches == 0 {
		return 0.0
	}

	// Coverage ratio: what fraction of URL segments matched
	coverage := float64(matches) / float64(len(urlSegments))
	if coverage >= 0.6 {
		return 0.6
	}
	if coverage > 0 {
		return 0.4
	}
	return 0.0
}

// ScoreTemporalAxis scores temporal proximity of two findings.
func ScoreTemporalAxis(a, b time.Time, cfg MatchConfig) float64 {
	if a.IsZero() || b.IsZero() {
		return 0.2
	}

	diff := a.Sub(b)
	if diff < 0 {
		diff = -diff
	}

	switch {
	case diff <= cfg.SameCycleWindow:
		return 1.0
	case diff <= cfg.RecentWindow:
		return 0.8
	case diff <= cfg.WeekWindow:
		return 0.5
	default:
		return 0.2
	}
}

// ComputeCorrelationScore computes the weighted score across all axes.
func ComputeCorrelationScore(sast, dast *RawFinding, hierarchy *CWEHierarchy, cfg MatchConfig) (AxisScores, float64) {
	scores := AxisScores{
		CWE:       ScoreCWEAxis(sast.CWEID, dast.CWEID, hierarchy),
		Parameter: ScoreParameterAxis(sast.CodeSnippet, dast.Parameter),
		Endpoint:  ScoreEndpointAxis(dast.URL, sast.FilePath),
		Temporal:  ScoreTemporalAxis(sast.FoundAt, dast.FoundAt, cfg),
	}
	return scores, scores.Total()
}

// RiskConfig holds parameters for composite risk scoring.
type RiskConfig struct {
	AssetCriticality string // critical, high, medium, low
}

// ComputeRiskScore calculates the composite risk score.
func ComputeRiskScore(baseSeverity string, exploitAvailable, activelyExploited bool, confidence Confidence, assetCriticality string) float64 {
	base := severityToScore(baseSeverity)

	exploitMult := 1.0
	if activelyExploited {
		exploitMult = 1.6
	} else if exploitAvailable {
		exploitMult = 1.3
	}

	assetMult := 1.0
	switch assetCriticality {
	case "critical":
		assetMult = 1.4
	case "high":
		assetMult = 1.2
	case "low":
		assetMult = 0.8
	}

	corrBoost := 1.0
	switch confidence {
	case ConfidenceHigh:
		corrBoost = 1.2
	case ConfidenceMedium:
		corrBoost = 1.1
	}

	return math.Min(base*exploitMult*assetMult*corrBoost, 10.0)
}

// RiskScoreToSeverity maps a risk score to a severity label.
func RiskScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 1.0:
		return "low"
	default:
		return "info"
	}
}

func severityToScore(severity string) float64 {
	switch severity {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	case "info":
		return 0.5
	default:
		return 5.0
	}
}

func normalizeParamName(name string) string {
	// Convert camelCase to snake_case, then lowercase
	return strings.ToLower(camelToSnake(name))
}

func camelToSnake(s string) string {
	var result []rune
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			result = append(result, '_')
		}
		result = append(result, unicode.ToLower(r))
	}
	return string(result)
}

func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

func extractURLSegments(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	var segments []string
	for _, p := range parts {
		// Skip empty, version prefixes, and parameter placeholders
		if p == "" || p == "api" || p == "v1" || p == "v2" || p == "v3" || strings.HasPrefix(p, "{") {
			continue
		}
		segments = append(segments, strings.ToLower(p))
	}
	return segments
}

func extractPathSegments(filePath string) []string {
	parts := strings.Split(filePath, "/")
	var segments []string
	for _, p := range parts {
		// Extract meaningful names from file paths
		p = strings.TrimSuffix(p, ".go")
		p = strings.TrimSuffix(p, ".java")
		p = strings.TrimSuffix(p, ".py")
		p = strings.TrimSuffix(p, ".js")
		p = strings.TrimSuffix(p, ".ts")
		p = strings.ToLower(p)
		// Skip common non-meaningful segments
		if p == "" || p == "internal" || p == "pkg" || p == "src" || p == "main" || p == "lib" || p == "app" {
			continue
		}
		// Strip common suffixes
		p = strings.TrimSuffix(p, "controller")
		p = strings.TrimSuffix(p, "handler")
		p = strings.TrimSuffix(p, "service")
		p = strings.TrimSuffix(p, "dao")
		p = strings.TrimSuffix(p, "repo")
		p = strings.TrimSuffix(p, "repository")
		if p != "" {
			segments = append(segments, p)
		}
	}
	return segments
}
