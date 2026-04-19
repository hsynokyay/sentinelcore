package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	corr "github.com/sentinelcore/sentinelcore/pkg/correlation"
)

// SurfaceCorrelation links a surface entry to a correlated finding or code signal.
type SurfaceCorrelation struct {
	SurfaceID    string          `json:"surface_id"`
	FindingID    string          `json:"finding_id,omitempty"`
	MatchType    SurfaceMatchType `json:"match_type"`
	Score        float64         `json:"score"`
	Confidence   string          `json:"confidence"` // high, medium, low
	Detail       string          `json:"detail"`
}

// SurfaceMatchType describes how a surface entry was matched.
type SurfaceMatchType string

const (
	MatchExactURL     SurfaceMatchType = "exact_url"       // URL matches exactly
	MatchPathPrefix   SurfaceMatchType = "path_prefix"     // URL path is a prefix match
	MatchEndpointCWE  SurfaceMatchType = "endpoint_cwe"    // endpoint + CWE category match
	MatchFormAction   SurfaceMatchType = "form_action"     // form action matches finding URL
	MatchParameterName SurfaceMatchType = "parameter_name" // form field matches finding parameter
)

// EnrichmentResult holds all correlations produced for an inventory.
type EnrichmentResult struct {
	Correlations []SurfaceCorrelation `json:"correlations"`
	Stats        EnrichmentStats      `json:"stats"`
}

// EnrichmentStats summarizes enrichment outcomes.
type EnrichmentStats struct {
	TotalCorrelations int            `json:"total_correlations"`
	ByMatchType       map[string]int `json:"by_match_type"`
	ByConfidence      map[string]int `json:"by_confidence"`
	EnrichedEntries   int            `json:"enriched_entries"`
}

// EnrichInventory links surface entries to findings using deterministic matching.
// Matching is based on URL overlap, path prefix, form action, and parameter names.
// No speculative mappings — every correlation has an explicit match type and score.
func EnrichInventory(inv *SurfaceInventory, findings []*corr.RawFinding) *EnrichmentResult {
	result := &EnrichmentResult{
		Stats: EnrichmentStats{
			ByMatchType:  make(map[string]int),
			ByConfidence: make(map[string]int),
		},
	}

	// Index findings by normalized URL and by parameter.
	findingsByURL := make(map[string][]*corr.RawFinding)
	findingsByParam := make(map[string][]*corr.RawFinding)
	for _, f := range findings {
		if f.URL != "" {
			normalized := NormalizeURL(f.URL)
			if normalized != "" {
				findingsByURL[normalized] = append(findingsByURL[normalized], f)
			}
		}
		if f.Parameter != "" {
			findingsByParam[strings.ToLower(f.Parameter)] = append(findingsByParam[strings.ToLower(f.Parameter)], f)
		}
	}

	enriched := make(map[string]bool)

	for _, entry := range inv.Entries {
		// 1. Exact URL match
		if matches, ok := findingsByURL[entry.URL]; ok {
			for _, f := range matches {
				sc := SurfaceCorrelation{
					SurfaceID:  entry.ID,
					FindingID:  f.ID,
					MatchType:  MatchExactURL,
					Score:      1.0,
					Confidence: "high",
					Detail:     "Surface URL exactly matches finding URL",
				}
				result.Correlations = append(result.Correlations, sc)
				enriched[entry.ID] = true
				entry.FindingIDs = appendUnique(entry.FindingIDs, f.ID)
			}
		}

		// 2. Path prefix match — surface URL is a prefix of finding URL or vice versa
		entryPath := extractPath(entry.URL)
		if entryPath != "" && entryPath != "/" {
			for findingURL, fList := range findingsByURL {
				if findingURL == entry.URL {
					continue // already matched exactly
				}
				findingPath := extractPath(findingURL)
				if findingPath != "" && (strings.HasPrefix(findingPath, entryPath) || strings.HasPrefix(entryPath, findingPath)) {
					overlap := pathOverlap(entryPath, findingPath)
					if overlap >= 0.5 {
						for _, f := range fList {
							sc := SurfaceCorrelation{
								SurfaceID:  entry.ID,
								FindingID:  f.ID,
								MatchType:  MatchPathPrefix,
								Score:      overlap,
								Confidence: scoreToConfidence(overlap),
								Detail:     "Surface URL path overlaps with finding URL path",
							}
							result.Correlations = append(result.Correlations, sc)
							enriched[entry.ID] = true
							entry.FindingIDs = appendUnique(entry.FindingIDs, f.ID)
						}
					}
				}
			}
		}

		// 3. Form action → finding URL match
		if entry.Type == SurfaceForm && entry.Metadata.FormAction != "" {
			actionNorm := NormalizeURL(ResolveURL(entry.Metadata.FormAction, entry.URL))
			if actionNorm != "" {
				if matches, ok := findingsByURL[actionNorm]; ok {
					for _, f := range matches {
						sc := SurfaceCorrelation{
							SurfaceID:  entry.ID,
							FindingID:  f.ID,
							MatchType:  MatchFormAction,
							Score:      0.9,
							Confidence: "high",
							Detail:     "Form action URL matches finding URL",
						}
						result.Correlations = append(result.Correlations, sc)
						enriched[entry.ID] = true
						entry.FindingIDs = appendUnique(entry.FindingIDs, f.ID)
					}
				}
			}
		}

		// 4. Parameter name match — form fields match finding parameters
		if entry.Type == SurfaceForm {
			for _, field := range entry.Metadata.Fields {
				if field.Name == "" {
					continue
				}
				fieldLower := strings.ToLower(field.Name)
				if matches, ok := findingsByParam[fieldLower]; ok {
					for _, f := range matches {
						sc := SurfaceCorrelation{
							SurfaceID:  entry.ID,
							FindingID:  f.ID,
							MatchType:  MatchParameterName,
							Score:      0.8,
							Confidence: "medium",
							Detail:     "Form field name matches finding parameter: " + field.Name,
						}
						result.Correlations = append(result.Correlations, sc)
						enriched[entry.ID] = true
						entry.FindingIDs = appendUnique(entry.FindingIDs, f.ID)
					}
				}
			}
		}
	}

	// Compute stats.
	result.Stats.TotalCorrelations = len(result.Correlations)
	result.Stats.EnrichedEntries = len(enriched)
	for _, c := range result.Correlations {
		result.Stats.ByMatchType[string(c.MatchType)]++
		result.Stats.ByConfidence[c.Confidence]++
	}

	// Recompute inventory stats after enrichment.
	inv.ComputeStats()

	return result
}

// CorrelationFingerprint generates a deterministic ID for a surface correlation.
func CorrelationFingerprint(surfaceID, findingID string, matchType SurfaceMatchType) string {
	h := sha256.New()
	h.Write([]byte(surfaceID))
	h.Write([]byte("|"))
	h.Write([]byte(findingID))
	h.Write([]byte("|"))
	h.Write([]byte(string(matchType)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// extractPath returns the path component of a URL.
func extractPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Path
}

// pathOverlap computes the fraction of shared path segments.
func pathOverlap(a, b string) float64 {
	segsA := splitPath(a)
	segsB := splitPath(b)
	if len(segsA) == 0 || len(segsB) == 0 {
		return 0
	}

	shared := 0
	maxLen := len(segsA)
	if len(segsB) > maxLen {
		maxLen = len(segsB)
	}
	minLen := len(segsA)
	if len(segsB) < minLen {
		minLen = len(segsB)
	}

	for i := 0; i < minLen; i++ {
		if strings.EqualFold(segsA[i], segsB[i]) {
			shared++
		}
	}

	return float64(shared) / float64(maxLen)
}

// splitPath splits a URL path into segments, ignoring empty segments.
func splitPath(path string) []string {
	var segs []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

// scoreToConfidence maps a score to a confidence level.
func scoreToConfidence(score float64) string {
	switch {
	case score >= 0.8:
		return "high"
	case score >= 0.5:
		return "medium"
	case score >= 0.3:
		return "low"
	default:
		return ""
	}
}
